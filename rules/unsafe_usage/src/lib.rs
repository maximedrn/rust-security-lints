#![feature(rustc_private)]

extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;

use rustc_errors::{
    Diag,
    DiagCtxtHandle,
    Diagnostic,
    EmissionGuarantee,
    Level,
};
use rustc_hir::{
    BlockCheckMode,
    Expr,
    ExprKind,
    HeaderSafety,
    Item,
    ItemKind,
    Safety,
    UnsafeSource,
};
use rustc_lint::{LateContext, LateLintPass, LintContext, LintStore};
use rustc_middle::ty::TyCtxt;
use rustc_session::{Session, declare_lint, declare_lint_pass};

declare_lint! {
    pub SECURITY_UNSAFE_USAGE,
    Deny,
    "Detects usage of unsafe blocks, unsafe functions, unsafe
    traits and unsafe implementations."
}

declare_lint_pass!(SecurityUnsafeUsage => [SECURITY_UNSAFE_USAGE]);

/// Wraps a static string so it can be passed to `emit_span_lint`, which
/// requires a type implementing `Diagnostic` rather than a plain closure.
///
/// # Fields
/// - `0` (`&'static str`) - The lint message to display at the flagged site.
struct LintMsg(&'static str);

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for LintMsg {
    /// Converts this message into a `Diag` at the given diagnostic level.
    ///
    /// # Arguments
    /// - `diagnostic_context` (`DiagCtxtHandle<'a>`) - Handle to the
    ///   compiler's diagnostic context, used to create the `Diag`.
    /// - `level` (`Level`) - The severity level at which the diagnostic will
    ///   be emitted.
    ///
    /// # Returns
    /// A `Diag<'a, G>` ready to be emitted by the compiler.
    fn into_diag(
        self,
        diagnostic_context: DiagCtxtHandle<'a>,
        level: Level,
    ) -> Diag<'a, G> {
        Diag::new(diagnostic_context, level, self.0)
    }
}

impl<'tcx> LateLintPass<'tcx> for SecurityUnsafeUsage {
    /// Flags explicitly user-written `unsafe` blocks. Compiler-generated
    /// unsafe blocks (e.g. from desugaring) are ignored via the
    /// `UnsafeSource::UserProvided` guard.
    ///
    /// # Arguments
    /// - `context` (`&LateContext<'tcx>`) - The lint context, providing access
    ///   to diagnostic utilities.
    /// - `expression` (`&'tcx Expr<'tcx>`) - The HIR expression being
    ///   inspected. Only `ExprKind::Block` nodes with
    ///   `BlockCheckMode::UnsafeBlock(UnsafeSource::UserProvided)` are acted
    ///   upon.
    ///
    /// # Returns
    /// `()` - Emits a lint diagnostic as a side effect if a violation is
    /// found.
    fn check_expr(
        &mut self,
        context: &LateContext<'tcx>,
        expression: &'tcx Expr<'tcx>,
    ) {
        if let ExprKind::Block(block, _) = &expression.kind
            && let BlockCheckMode::UnsafeBlock(UnsafeSource::UserProvided) =
                block.rules
        {
            context.emit_span_lint(
                SECURITY_UNSAFE_USAGE,
                expression.span,
                LintMsg("Usage of unsafe block detected."),
            );
        }
    }

    /// Flags unsafe function definitions, unsafe trait declarations, and
    /// unsafe trait implementations (`unsafe impl`).
    ///
    /// # Arguments
    /// - `context` (`&LateContext<'tcx>`) - The lint context, providing access
    ///   to diagnostic utilities.
    /// - `item` (`&'tcx Item<'tcx>`) - The HIR item being inspected.
    ///   `ItemKind::Fn`, `ItemKind::Trait`, and `ItemKind::Impl` nodes are
    ///   acted upon when they carry the `unsafe` modifier.
    ///
    /// # Returns
    /// `()` - Emits a lint diagnostic as a side effect if a violation is
    /// found.
    fn check_item(
        &mut self,
        context: &LateContext<'tcx>,
        item: &'tcx Item<'tcx>,
    ) {
        match &item.kind {
            ItemKind::Fn { sig, .. } => {
                if matches!(
                    sig.header.safety,
                    HeaderSafety::Normal(Safety::Unsafe)
                ) {
                    context.emit_span_lint(
                        SECURITY_UNSAFE_USAGE,
                        item.span,
                        LintMsg("Unsafe function detected."),
                    );
                }
            },

            ItemKind::Trait(_, _, safety, _, _, _, _)
                if *safety == Safety::Unsafe =>
            {
                context.emit_span_lint(
                    SECURITY_UNSAFE_USAGE,
                    item.span,
                    LintMsg("Unsafe trait detected."),
                );
            },

            ItemKind::Impl(impl_) => {
                if let Some(trait_impl) = impl_.of_trait
                    && trait_impl.safety == Safety::Unsafe
                {
                    context.emit_span_lint(
                        SECURITY_UNSAFE_USAGE,
                        item.span,
                        LintMsg("Unsafe impl detected."),
                    );
                }
            },

            _ => {},
        }
    }
}

/// Registers the lint with the compiler's lint store. Called once when the
/// Dylint library is loaded.
///
/// # Arguments
/// - `session` (`&Session`) - The current compiler session, used to initialize
///   Dylint's configuration system.
/// - `lint_store` (`&mut LintStore`) - The compiler's lint store into which
///   `SECURITY_UNSAFE_USAGE` and its late pass are registered.
///
/// # Returns
/// `()` - Registration is performed as a side effect.
#[unsafe(no_mangle)]
pub fn register_lints(session: &Session, lint_store: &mut LintStore) {
    dylint_linting::init_config(session);
    lint_store.register_lints(&[SECURITY_UNSAFE_USAGE]);
    lint_store
        .register_late_pass(|_: TyCtxt<'_>| Box::new(SecurityUnsafeUsage));
}

dylint_linting::dylint_library!();

#[cfg(test)]
mod tests {
    use dylint_testing::ui::Test;

    /// Runs UI tests against the `ui` directory, verifying that
    /// `SECURITY_UNSAFE_USAGE` emits the expected diagnostics for unsafe
    /// blocks, functions, traits, and implementations, and stays silent on
    /// safe code.
    #[test]
    fn ui() {
        Test::src_base(env!("CARGO_PKG_NAME"), "ui")
            .rustc_flags(["--edition=2024", "-Z", "ui-testing"])
            .run();
    }
}

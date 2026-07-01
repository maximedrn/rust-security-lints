#![feature(rustc_private)]

extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

use rustc_errors::{
    Diag,
    DiagCtxtHandle,
    Diagnostic,
    EmissionGuarantee,
    Level,
};
use rustc_hir::{Expr, ExprKind, Item, ItemKind};
use rustc_lint::{LateContext, LateLintPass, LintContext, LintStore};
use rustc_middle::ty::TyCtxt;
use rustc_session::{Session, declare_lint, declare_lint_pass};

declare_lint! {
    pub SECURITY_INDEXING_USAGE,
    Deny,
    "Detects usage of indexing and slicing operations."
}
declare_lint_pass!(SecurityIndexingUsage => [SECURITY_INDEXING_USAGE]);

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
    /// - `level` (`Level`) - The severity level (error, warning, etc.) at
    ///   which the diagnostic will be emitted.
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

impl<'tcx> LateLintPass<'tcx> for SecurityIndexingUsage {
    /// Flags any use of the index operator `[]`, whether with a literal,
    /// a range (slicing), or a dynamic value. All three forms can panic at
    /// runtime on out-of-bounds access and should be replaced with safer
    /// alternatives such as `.get()`.
    ///
    /// # Arguments
    /// - `context` (`&LateContext<'tcx>`) - The lint context, providing access
    ///   to type information and diagnostic utilities.
    /// - `expression` (`&'tcx Expr<'tcx>`) - The HIR expression being
    ///   inspected. Only `ExprKind::Index` nodes are acted upon.
    ///
    /// # Returns
    /// `()` - Emits a lint diagnostic as a side effect if a violation is
    /// found.
    fn check_expr(
        &mut self,
        context: &LateContext<'tcx>,
        expression: &'tcx Expr<'tcx>,
    ) {
        if let ExprKind::Index(_, index_expr, _) = &expression.kind {
            let msg = match &index_expr.kind {
                ExprKind::Struct(_, _, _) => {
                    "Usage of slicing operation detected."
                },
                _ => "Usage of indexing operation detected.",
            };
            context.emit_span_lint(
                SECURITY_INDEXING_USAGE,
                expression.span,
                LintMsg(msg),
            );
        }
    }

    /// Flags any `impl Index` or `impl IndexMut` block. Implementing these
    /// traits introduces the `[]` operator on a type, which carries the same
    /// panic risk as direct indexing and warrants explicit review.
    ///
    /// # Arguments
    /// - `context` (`&LateContext<'tcx>`) - The lint context, providing access
    ///   to language item resolution and diagnostic utilities.
    /// - `item` (`&'tcx Item<'tcx>`) - The HIR item being inspected. Only
    ///   `ItemKind::Impl` nodes that implement `Index` or `IndexMut` are acted
    ///   upon.
    ///
    /// # Returns
    /// `()` - Emits a lint diagnostic as a side effect if a violation is
    /// found.
    fn check_item(
        &mut self,
        context: &LateContext<'tcx>,
        item: &'tcx Item<'tcx>,
    ) {
        if let ItemKind::Impl(implementation) = &item.kind
            && let Some(trait_ref) = implementation.of_trait
            && let Some(def_id) = trait_ref.trait_ref.path.res.opt_def_id()
            && (context.tcx.lang_items().index_trait() == Some(def_id)
                || context.tcx.lang_items().index_mut_trait() == Some(def_id))
        {
            context.emit_span_lint(
                SECURITY_INDEXING_USAGE,
                item.span,
                LintMsg("Implementation of Index/IndexMut trait detected."),
            );
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
///   `SECURITY_INDEXING_USAGE` and its late pass are registered.
///
/// # Returns
/// `()` - Registration is performed as a side effect.
#[unsafe(no_mangle)]
pub fn register_lints(session: &Session, lint_store: &mut LintStore) {
    dylint_linting::init_config(session);
    lint_store.register_lints(&[SECURITY_INDEXING_USAGE]);
    lint_store
        .register_late_pass(|_: TyCtxt<'_>| Box::new(SecurityIndexingUsage));
}

dylint_linting::dylint_library!();

#[cfg(test)]
mod tests {
    use dylint_testing::ui::Test;

    /// Runs UI tests against the `ui` directory, verifying that
    /// `SECURITY_INDEXING_USAGE` emits the expected diagnostics for each
    /// test case.
    #[test]
    fn ui() {
        Test::src_base(env!("CARGO_PKG_NAME"), "ui")
            .rustc_flags(["--edition=2024", "-Z", "ui-testing"])
            .run();
    }
}

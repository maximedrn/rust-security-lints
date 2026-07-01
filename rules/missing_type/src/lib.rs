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
use rustc_hir::{Body, BodyId, ClosureKind, Expr, ExprKind, LetStmt, PatKind};
use rustc_lint::{LateContext, LateLintPass, LintContext, LintStore};
use rustc_middle::ty::TyCtxt;
use rustc_session::{Session, declare_lint, declare_lint_pass};

declare_lint! {
    pub MISSING_LET_TYPE,
    Warn,
    "Detects missing explicit type annotation on let bindings."
}

declare_lint! {
    pub MISSING_CLOSURE_PARAM_TYPE,
    Warn,
    "Detects missing explicit type annotation on closure parameters."
}

declare_lint_pass!(MissingType => [
    MISSING_LET_TYPE,
    MISSING_CLOSURE_PARAM_TYPE
]);

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

impl<'tcx> LateLintPass<'tcx> for MissingType {
    /// Flags `let` bindings that have no explicit type annotation, unless the
    /// pattern is `_`, the binding comes from a macro expansion, or the span
    /// is the result of compiler desugaring (async, `?`, `for`, etc.).
    ///
    /// # Arguments
    /// - `context` (`&LateContext<'tcx>`) - The lint context, providing access
    ///   to type information and diagnostic utilities.
    /// - `local` (`&'tcx LetStmt<'tcx>`) - The `let` statement being
    ///   inspected. Only statements whose `ty` field is `None` are flagged.
    ///
    /// # Returns
    /// `()` - Emits a lint diagnostic as a side effect if a violation is
    /// found.
    fn check_local(
        &mut self,
        context: &LateContext<'tcx>,
        local: &'tcx LetStmt<'tcx>,
    ) {
        if matches!(local.pat.kind, PatKind::Wild) {
            return;
        }

        let Some(body_id): Option<BodyId> = context.enclosing_body else {
            return;
        };

        if context.tcx.hir_body(body_id).value.span.from_expansion() {
            return;
        }

        if local.span.from_expansion() {
            return;
        }

        if local.span.desugaring_kind().is_some() {
            return;
        }

        if local.ty.is_none() {
            context.emit_span_lint(
                MISSING_LET_TYPE,
                local.pat.span,
                LintMsg("Missing explicit type annotation on let binding."),
            );
        }
    }

    /// Flags closure parameters that have no explicit type annotation, unless
    /// the parameter pattern is `_` or the closure is a compiler-generated
    /// coroutine (async blocks, async functions).
    ///
    /// # Arguments
    /// - `context` (`&LateContext<'tcx>`) - The lint context, providing access
    ///   to HIR bodies and diagnostic utilities.
    /// - `expression` (`&'tcx Expr<'tcx>`) - The expression being inspected.
    ///   Only `ExprKind::Closure` nodes are acted upon.
    ///
    /// # Returns
    /// `()` - Emits a lint diagnostic as a side effect for each parameter
    ///   that is missing a type annotation.
    fn check_expr(
        &mut self,
        context: &LateContext<'tcx>,
        expression: &'tcx Expr<'tcx>,
    ) {
        if expression.span.from_expansion() {
            return;
        }

        let ExprKind::Closure(closure): &ExprKind<'tcx> = &expression.kind
        else {
            return;
        };

        if matches!(closure.kind, ClosureKind::Coroutine(_)) {
            return;
        }

        let body: &Body<'_> = context.tcx.hir_body(closure.body);

        for param in body.params {
            if matches!(param.pat.kind, PatKind::Wild) {
                continue;
            }

            if param.ty_span.is_empty() || param.ty_span == param.pat.span {
                context.emit_span_lint(
                    MISSING_CLOSURE_PARAM_TYPE,
                    param.pat.span,
                    LintMsg(
                        "Closure parameter missing explicit type annotation.",
                    ),
                );
            }
        }
    }
}

/// Registers both lints with the compiler's lint store. Called once when the
/// Dylint library is loaded.
///
/// # Arguments
/// - `session` (`&Session`) - The current compiler session, used to initialize
///   Dylint's configuration system.
/// - `lint_store` (`&mut LintStore`) - The compiler's lint store into which
///   `MISSING_LET_TYPE`, `MISSING_CLOSURE_PARAM_TYPE`, and their shared late
///   pass are registered.
///
/// # Returns
/// `()` - Registration is performed as a side effect.
#[unsafe(no_mangle)]
pub fn register_lints(session: &Session, lint_store: &mut LintStore) {
    dylint_linting::init_config(session);
    lint_store.register_lints(&[MISSING_LET_TYPE, MISSING_CLOSURE_PARAM_TYPE]);
    lint_store.register_late_pass(|_: TyCtxt<'_>| Box::new(MissingType));
}

dylint_linting::dylint_library!();

#[cfg(test)]
mod tests {
    use dylint_testing::ui::Test;

    /// Runs UI tests against the `ui` directory, verifying that
    /// `MISSING_LET_TYPE` and `MISSING_CLOSURE_PARAM_TYPE` emit the expected
    /// diagnostics and stay silent on exempt patterns.
    #[test]
    fn ui() {
        Test::src_base(env!("CARGO_PKG_NAME"), "ui")
            .rustc_flags(["--edition=2024", "-Z", "ui-testing"])
            .run();
    }
}

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
use rustc_hir::{Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass, LintContext, LintStore};
use rustc_middle::ty::TyCtxt;
use rustc_session::{Session, declare_lint, declare_lint_pass};
use rustc_span::symbol::Symbol;

declare_lint! {
    pub SECURITY_PANIC_USAGE,
    Deny,
    "Detects constructs that may panic at runtime."
}

declare_lint_pass!(SecurityPanicUsage => [SECURITY_PANIC_USAGE]);

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

/// Wraps an owned string for use as a dynamic lint message with
/// `emit_span_lint`.
///
/// # Fields
/// - `0` (`String`) - The lint message to display at the flagged site.
struct LintMsgOwned(String);

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for LintMsgOwned {
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

/// Identifies the panic backend behind a call by inspecting the definition
/// path of the callee. Used to produce a precise diagnostic message.
#[derive(Debug, Clone, Copy)]
enum PanicBackend {
    /// Any function inside a `panicking` module (e.g. `core::panicking`).
    PanickingModule,
    /// The `panic_fmt` internal function.
    PanicFmt,
    /// The `panic_display` internal function.
    PanicDisplay,
    /// The `assert_failed` internal function emitted by `assert!`.
    AssertFailed,
    /// The `begin_panic` function used by older panic implementations.
    BeginPanic,
}

impl PanicBackend {
    /// Attempts to identify a panic backend from a definition path string.
    ///
    /// # Arguments
    /// - `path` (`&str`) - The fully-qualified definition path of the callee
    ///   as returned by `TyCtxt::def_path_str`.
    ///
    /// # Returns
    /// `Some(PanicBackend)` if the path matches a known panic backend,
    /// `None` otherwise.
    fn from_def_path(path: &str) -> Option<Self> {
        if path.contains("panicking::") {
            Some(Self::PanickingModule)
        } else if path.contains("panic_fmt") {
            Some(Self::PanicFmt)
        } else if path.contains("panic_display") {
            Some(Self::PanicDisplay)
        } else if path.contains("assert_failed") {
            Some(Self::AssertFailed)
        } else if path.contains("begin_panic") {
            Some(Self::BeginPanic)
        } else {
            None
        }
    }
}

impl<'tcx> LateLintPass<'tcx> for SecurityPanicUsage {
    /// Flags calls to `.unwrap()` and `.expect()` by method name, as well as
    /// direct calls to internal panic backends such as `panic_fmt`,
    /// `panic_display`, `assert_failed`, and `begin_panic`.
    ///
    /// `.unwrap()` and `.expect()` are detected by method name rather than
    /// diagnostic item because the relevant `sym` entries are not stable
    /// across nightly versions.
    ///
    /// # Arguments
    /// - `context` (`&LateContext<'tcx>`) - The lint context, providing access
    ///   to type-check results and diagnostic utilities.
    /// - `expression` (`&'tcx Expr<'tcx>`) - The HIR expression being
    ///   inspected. Both `ExprKind::MethodCall` and `ExprKind::Call` nodes are
    ///   acted upon.
    ///
    /// # Returns
    /// `()` - Emits a lint diagnostic as a side effect if a violation is
    /// found.
    fn check_expr(
        &mut self,
        context: &LateContext<'tcx>,
        expression: &'tcx Expr<'tcx>,
    ) {
        if let ExprKind::MethodCall(method, _, _, _) = &expression.kind
            && (method.ident.name == Symbol::intern("unwrap")
                || method.ident.name == Symbol::intern("expect"))
        {
            context.emit_span_lint(
                SECURITY_PANIC_USAGE,
                expression.span,
                LintMsg("Call to panic backend `unwrap/expect` detected."),
            );
        }

        if let ExprKind::Call(func, _) = &expression.kind
            && let ExprKind::Path(path) = &func.kind
            && let Some(def_id) =
                context.qpath_res(path, func.hir_id).opt_def_id()
            && let Some(kind) =
                PanicBackend::from_def_path(&context.tcx.def_path_str(def_id))
        {
            context.emit_span_lint(
                SECURITY_PANIC_USAGE,
                expression.span.source_callsite(),
                LintMsgOwned(format!(
                    "Call to panic backend `{kind:?}` detected."
                )),
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
///   `SECURITY_PANIC_USAGE` and its late pass are registered.
///
/// # Returns
/// `()` - Registration is performed as a side effect.
#[unsafe(no_mangle)]
pub fn register_lints(session: &Session, lint_store: &mut LintStore) {
    dylint_linting::init_config(session);
    lint_store.register_lints(&[SECURITY_PANIC_USAGE]);
    lint_store
        .register_late_pass(|_: TyCtxt<'_>| Box::new(SecurityPanicUsage));
}

dylint_linting::dylint_library!();

#[cfg(test)]
mod tests {
    use dylint_testing::ui::Test;

    /// Runs UI tests against the `ui` directory, verifying that
    /// `SECURITY_PANIC_USAGE` emits the expected diagnostics for calls to
    /// panic-prone functions and stays silent on safe alternatives.
    #[test]
    fn ui() {
        Test::src_base(env!("CARGO_PKG_NAME"), "ui")
            .rustc_flags(["--edition=2024", "-Z", "ui-testing"])
            .run();
    }
}

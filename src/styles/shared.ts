import { css } from 'lit'

/**
 * Shared styles for all Attestto web components.
 *
 * All visual properties use CSS custom properties (--attestto-*)
 * so embedders can theme without touching shadow DOM internals.
 */
export const sharedStyles = css`
  *,
  *::before,
  *::after {
    box-sizing: border-box;
  }

  :host {
    --attestto-font: system-ui, -apple-system, sans-serif;
    --attestto-text: #1a1a2e;
    --attestto-text-muted: #64748b;
    --attestto-primary: #594FD3;
    --attestto-primary-hover: #7B72ED;
    --attestto-success: #16a34a;
    --attestto-success-bg: #dcfce7;
    --attestto-warning: #d97706;
    --attestto-warning-bg: #fef3c7;
    --attestto-border: #e2e8f0;
    --attestto-bg: #f8fafc;
    --attestto-bg-hover: #eef2ff;
    --attestto-bg-card: #ffffff;
    --attestto-bg-code: #f1f5f9;
    --attestto-bg-code-hover: #e2e8f0;
  }
`

import HoneyPromptLogo from './assets/honeyprompt-logo.png';

export default function LoadingState({ label = 'Loading HoneyPrompt...', compact = false, fullScreen = false }) {
  return (
    <div className={`hp-loading${compact ? ' hp-loading-compact' : ''}${fullScreen ? ' hp-loading-fullscreen' : ''}`} role="status" aria-live="polite">
      <span className="hp-loading-mark"><img src={HoneyPromptLogo} alt="" /></span>
      <span className="hp-loading-label">{label}</span>
    </div>
  );
}
import React from 'react';

/**
 * HoneyBeeSvg - Futuristic Cybernetic Honey Bee vector with animated wings,
 * soft glow aura, and light/honey particle trail.
 */
export function HoneyBeeSvg({ size = 'md', className = '' }) {
  const sizeMap = {
    xs: { w: 24, h: 21 },
    sm: { w: 32, h: 28 },
    md: { w: 46, h: 40 },
    lg: { w: 68, h: 60 },
    xl: { w: 88, h: 77 },
  };

  const dims = sizeMap[size] || sizeMap.md;

  return (
    <div className={`hp-bee-flight hp-bee-${size} ${className}`} aria-hidden="true">
      <svg
        width={dims.w}
        height={dims.h}
        viewBox="0 0 80 70"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="hp-bee-svg"
      >
        <defs>
          {/* Cyber Gold Metallic Gradient */}
          <linearGradient id="hp-bee-gold-grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#FFE57F" />
            <stop offset="40%" stopColor="#F5C518" />
            <stop offset="100%" stopColor="#D97706" />
          </linearGradient>

          {/* Cyber Titanium Carbon Gradient */}
          <linearGradient id="hp-bee-carbon-grad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#2D2926" />
            <stop offset="50%" stopColor="#1C1917" />
            <stop offset="100%" stopColor="#0F0E0D" />
          </linearGradient>

          {/* Holographic Wing Shimmer Gradient */}
          <linearGradient id="hp-bee-wing-grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="rgba(255, 245, 180, 0.85)" />
            <stop offset="45%" stopColor="rgba(200, 235, 255, 0.55)" />
            <stop offset="100%" stopColor="rgba(245, 197, 24, 0.25)" />
          </linearGradient>

          {/* Honey Energy Drop Gradient */}
          <radialGradient id="hp-bee-honey-drop" cx="35%" cy="35%" r="65%">
            <stop offset="0%" stopColor="#FFF7C2" />
            <stop offset="45%" stopColor="#F5C518" />
            <stop offset="100%" stopColor="#D97706" />
          </radialGradient>

          {/* Soft Golden Aura */}
          <radialGradient id="hp-bee-aura" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="rgba(245, 197, 24, 0.38)" />
            <stop offset="55%" stopColor="rgba(245, 197, 24, 0.12)" />
            <stop offset="100%" stopColor="rgba(245, 197, 24, 0)" />
          </radialGradient>
        </defs>

        {/* Ambient Soft Glow Behind Bee */}
        <circle className="hp-bee-ambient-glow" cx="40" cy="34" r="28" fill="url(#hp-bee-aura)" />

        {/* Honey / Light Energy Trail */}
        <g className="hp-bee-trail">
          <circle className="hp-trail-p1" cx="40" cy="52" r="2.2" fill="url(#hp-bee-honey-drop)" />
          <circle className="hp-trail-p2" cx="36" cy="56" r="1.6" fill="url(#hp-bee-honey-drop)" />
          <circle className="hp-trail-p3" cx="44" cy="60" r="1.8" fill="url(#hp-bee-honey-drop)" />
          <polygon className="hp-trail-p4" points="40,58 41.6,60.8 40,63.5 38.4,60.8" fill="#FFE57F" opacity="0.75" />
        </g>

        {/* Cyber Holographic Wings */}
        <g className="hp-bee-wings">
          {/* Left Wing */}
          <g className="hp-bee-wing-left">
            <path
              d="M36 26 C25 10, 8 15, 10 28 C12 37, 27 35, 36 28 Z"
              fill="url(#hp-bee-wing-grad)"
              stroke="#FFE57F"
              strokeWidth="0.8"
              strokeOpacity="0.85"
            />
            {/* Inner circuit lattice */}
            <path d="M32 25 C23 19, 16 22, 14 26" stroke="#FFE57F" strokeWidth="0.5" strokeOpacity="0.6" fill="none" />
            <path d="M25 22 C21 26, 19 30, 21 32" stroke="#FFE57F" strokeWidth="0.4" strokeOpacity="0.45" fill="none" />
          </g>

          {/* Right Wing */}
          <g className="hp-bee-wing-right">
            <path
              d="M44 26 C55 10, 72 15, 70 28 C68 37, 53 35, 44 28 Z"
              fill="url(#hp-bee-wing-grad)"
              stroke="#FFE57F"
              strokeWidth="0.8"
              strokeOpacity="0.85"
            />
            {/* Inner circuit lattice */}
            <path d="M48 25 C57 19, 64 22, 66 26" stroke="#FFE57F" strokeWidth="0.5" strokeOpacity="0.6" fill="none" />
            <path d="M55 22 C59 26, 61 30, 59 32" stroke="#FFE57F" strokeWidth="0.4" strokeOpacity="0.45" fill="none" />
          </g>
        </g>

        {/* Honey Bee Body Structure */}
        <g className="hp-bee-body-group">
          {/* Threat Sensor / Cyber Stinger */}
          <polygon
            points="40,53 37,44 43,44"
            fill="url(#hp-bee-carbon-grad)"
            stroke="#F5C518"
            strokeWidth="0.6"
          />
          <circle cx="40" cy="51" r="1.1" fill="#FFE57F" />

          {/* Abdomen Base Armor */}
          <ellipse cx="40" cy="37" rx="10" ry="12" fill="url(#hp-bee-gold-grad)" />

          {/* Carbon Fiber Shield Stripes */}
          <path
            d="M31 31 Q40 33.5 49 31 Q48.5 34.5 48 35.5 Q40 37.8 32 35.5 Q31.5 34.5 31 31 Z"
            fill="url(#hp-bee-carbon-grad)"
          />
          <path
            d="M32 38.5 Q40 40.8 48 38.5 Q47 42.5 46 43.5 Q40 45.5 34 43.5 Q33 42.5 32 38.5 Z"
            fill="url(#hp-bee-carbon-grad)"
          />

          {/* Cybernetic Accent Circuit Lines */}
          <line x1="35.5" y1="33" x2="44.5" y2="33" stroke="#FFE57F" strokeWidth="0.65" strokeOpacity="0.9" />
          <line x1="36.5" y1="40" x2="43.5" y2="40" stroke="#FFE57F" strokeWidth="0.65" strokeOpacity="0.9" />

          {/* Thorax Main Plating */}
          <path
            d="M33 21 C33 18, 47 18, 47 21 C48 26, 47 29, 40 29 C33 29, 32 26, 33 21 Z"
            fill="url(#hp-bee-carbon-grad)"
            stroke="#F5C518"
            strokeWidth="0.8"
          />

          {/* Sentinel Micro-Reactor Core */}
          <circle cx="40" cy="24" r="2.4" fill="#FFE57F" className="hp-bee-core" />
          <circle cx="40" cy="24" r="1.1" fill="#FFFFFF" />

          {/* Sentinel Optic Helmet / Head */}
          <ellipse
            cx="40" cy="15" rx="6.5" ry="5"
            fill="url(#hp-bee-carbon-grad)"
            stroke="#F5C518"
            strokeWidth="0.75"
          />

          {/* Dual Cyber Optic Sensors */}
          <ellipse cx="37" cy="14.5" rx="1.7" ry="2.1" fill="#FFE57F" />
          <ellipse cx="43" cy="14.5" rx="1.7" ry="2.1" fill="#FFE57F" />
          <circle cx="37" cy="14.5" r="0.65" fill="#FFFFFF" />
          <circle cx="43" cy="14.5" r="0.65" fill="#FFFFFF" />

          {/* Cyber Antennae / Signal Probes */}
          <path d="M38 11 Q36 6 32 7" stroke="#F5C518" strokeWidth="0.85" strokeLinecap="round" fill="none" />
          <circle cx="32" cy="7" r="1" fill="#FFE57F" />
          <path d="M42 11 Q44 6 48 7" stroke="#F5C518" strokeWidth="0.85" strokeLinecap="round" fill="none" />
          <circle cx="48" cy="7" r="1" fill="#FFE57F" />
        </g>
      </svg>
    </div>
  );
}

/**
 * HoneyPrompt Loading Component
 * Reusable across pages, API calls, chat processing, report generation, etc.
 */
export default function HoneyBeeLoader({
  label = 'HoneyPrompt is securing your request...',
  compact = false,
  fullScreen = false,
  inline = false,
  size,
  subtext,
  badge,
  className = '',
  style = {},
}) {
  const resolvedSize = size || (compact || inline ? 'sm' : fullScreen ? 'lg' : 'md');

  // Parse label to handle trailing "..." with animated cyber dots if present
  let text = label;
  let hasDots = false;
  if (typeof text === 'string' && text.endsWith('...')) {
    text = text.slice(0, -3);
    hasDots = true;
  }

  const containerClasses = [
    'hp-loading',
    'hp-bee-loader-root',
    compact && 'hp-loading-compact',
    fullScreen && 'hp-loading-fullscreen',
    inline && 'hp-loading-inline',
    `hp-loading-size-${resolvedSize}`,
    className,
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div
      className={containerClasses}
      style={style}
      role="status"
      aria-live="polite"
    >
      <div className="hp-bee-wrapper">
        <HoneyBeeSvg size={resolvedSize} />
      </div>

      {(text || subtext || badge) && (
        <div className="hp-loading-text-group">
          {badge && <span className="hp-loading-badge">{badge}</span>}
          <div className="hp-loading-label">
            <span>{text}</span>
            {hasDots ? (
              <span className="hp-loading-dots" aria-hidden="true">
                <span className="hp-loading-dot">.</span>
                <span className="hp-loading-dot">.</span>
                <span className="hp-loading-dot">.</span>
              </span>
            ) : null}
          </div>
          {subtext && <div className="hp-loading-subtext">{subtext}</div>}
        </div>
      )}
    </div>
  );
}

export { HoneyBeeLoader as Loading, HoneyBeeLoader as LoadingState };

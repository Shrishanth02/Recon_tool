// Minimal inline icon set (stroke-based, 24x24 viewBox).
const PATHS = {
  globe: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18" />
    </>
  ),
  radar: (
    <>
      <path d="M12 12L4 6" />
      <path d="M19.4 15A8 8 0 1 0 9 19.4" />
      <path d="M16 12a4 4 0 1 0-4 4" />
      <circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none" />
    </>
  ),
  folder: (
    <>
      <path d="M3 7a2 2 0 0 1 2-2h4l2 2h6a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
    </>
  ),
  cpu: (
    <>
      <rect x="6" y="6" width="12" height="12" rx="2" />
      <path d="M9 9h6v6H9z" />
      <path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2" />
    </>
  ),
  id: (
    <>
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <circle cx="9" cy="11" r="2" />
      <path d="M5 16c0-1.7 1.8-3 4-3s4 1.3 4 3M15 9h4M15 13h4" />
    </>
  ),
  swap: (
    <>
      <path d="M7 4L3 8l4 4" />
      <path d="M3 8h13a4 4 0 0 1 0 8h-2" />
      <path d="M17 20l4-4-4-4" />
    </>
  ),
  terminal: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M7 9l3 3-3 3M13 15h4" />
    </>
  ),
  play: <path d="M7 5v14l12-7z" fill="currentColor" stroke="none" />,
  stop: <rect x="6" y="6" width="12" height="12" rx="2" fill="currentColor" stroke="none" />,
  download: (
    <>
      <path d="M12 3v12M7 10l5 5 5-5" />
      <path d="M5 21h14" />
    </>
  ),
  trash: (
    <>
      <path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M6 7l1 13a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-13" />
    </>
  ),
  shield: (
    <>
      <path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" />
      <path d="M9 12l2 2 4-4" />
    </>
  ),
  bolt: <path d="M13 2L4 14h6l-1 8 9-12h-6z" />,
  history: (
    <>
      <path d="M3 12a9 9 0 1 0 3-6.7L3 8" />
      <path d="M3 4v4h4M12 8v4l3 2" />
    </>
  ),
  check: <path d="M5 13l4 4L19 7" />,
  x: <path d="M6 6l12 12M18 6L6 18" />,
  pulse: <path d="M2 12h4l3 8 4-16 3 8h6" />,
  bug: (
    <>
      <rect x="8" y="8" width="8" height="11" rx="4" />
      <path d="M12 4v3M9 6l-1-2M15 6l1-2M8 11H4M8 15H3M16 11h4M16 15h5M8 19l-2 2M16 19l2 2" />
    </>
  ),
  folderTree: (
    <>
      <path d="M3 5h5l2 2h6a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H3z" />
    </>
  ),
  report: (
    <>
      <path d="M6 3h9l5 5v13a0 0 0 0 1 0 0H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z" />
      <path d="M14 3v6h6M9 13h6M9 17h6" />
    </>
  ),
  folderOpen: (
    <>
      <path d="M3 7a2 2 0 0 1 2-2h4l2 2h6a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
    </>
  ),
};

export default function Icon({ name, size = 18, className = "", strokeWidth = 1.7 }) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {PATHS[name] || null}
    </svg>
  );
}

import React from 'react';

const SHORTCUTS = [
  { key: 'A', label: 'Run structured analysis' },
  { key: 'R', label: 'Run raw syslog analysis' },
  { key: 'Tab', label: 'Cycle through threats' },
  { key: 'C', label: 'Toggle AI chat drawer' },
  { key: '?', label: 'Show this help' },
  { key: 'Esc', label: 'Close panels & modals' },
];

export default function ShortcutsModal({ onClose }) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e => e.stopPropagation()}>
        <div className="modal-title">⌨ Keyboard Shortcuts</div>
        <div className="modal-shortcuts">
          {SHORTCUTS.map(s => (
            <div key={s.key} className="modal-shortcut">
              <span>{s.label}</span>
              <span className="modal-key">{s.key}</span>
            </div>
          ))}
        </div>
        <div className="modal-close-hint">Press <strong>Esc</strong> or <strong>?</strong> to close</div>
      </div>
    </div>
  );
}

import { useState } from 'react';

export default function InfoTooltip({ term, definition, children }) {
  const [show, setShow] = useState(false);
  
  return (
    <span 
      className="relative inline-block"
      onMouseEnter={() => setShow(true)}
      onMouseLeave={() => setShow(false)}
    >
      <span className="border-b border-dotted border-gray-400 cursor-help">
        {children || term}
      </span>
      {show && (
        <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 
                        bg-gray-900 text-white text-xs rounded-lg p-3 w-64 z-50 shadow-xl pointer-events-none">
          <div className="font-semibold mb-1">{term}</div>
          <div className="opacity-90">{definition}</div>
          <div className="absolute top-full left-1/2 -translate-x-1/2 
                          border-4 border-transparent border-t-gray-900" />
        </div>
      )}
    </span>
  );
}

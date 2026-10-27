import React from 'react';

export default function OSILayer({ layer, label, value, note, warning }) {
  return (
    <div className={`flex items-start gap-2 py-2 ${warning ? 'text-red-700' : 'text-gray-700'}`}>
      <span className="bg-gray-100 text-gray-700 px-2 py-0.5 rounded text-xs font-mono flex-shrink-0">
        {layer}
      </span>
      <div className="flex-1 min-w-0">
        <div className="text-xs text-gray-500">{label}</div>
        <div className={`text-sm ${warning ? 'font-semibold' : ''} truncate`}>
          {value}
        </div>
        {note && <div className="text-xs text-gray-500 mt-0.5">{note}</div>}
      </div>
    </div>
  );
}

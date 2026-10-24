import React from 'react';

export default function ErrorState({ 
  title = "Không thể tải dữ liệu", 
  message = "Vui lòng thử lại sau", 
  onRetry,
  icon = "⚠️" 
}) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center">
      <div className="text-6xl mb-4">{icon}</div>
      <h3 className="text-lg font-semibold text-gray-900 mb-2">{title}</h3>
      <p className="text-gray-600 mb-6 max-w-md">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg font-medium"
        >
          🔄 Thử lại
        </button>
      )}
    </div>
  );
}

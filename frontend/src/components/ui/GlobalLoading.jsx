export default function GlobalLoading({ message = "Đang kết nối Manager..." }) {
  return (
    <div className="fixed inset-0 bg-white/80 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="text-center">
        <div className="inline-block w-12 h-12 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mb-4" />
        <div className="text-gray-700 font-medium">{message}</div>
        <div className="text-gray-500 text-sm mt-1">Vui lòng đợi...</div>
      </div>
    </div>
  );
}

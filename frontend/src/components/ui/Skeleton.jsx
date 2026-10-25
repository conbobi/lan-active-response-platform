export function Skeleton({ className = "", height = "1rem" }) {
  return (
    <div 
      className={`bg-gray-200 rounded animate-pulse ${className}`}
      style={{ height }}
    />
  );
}

export function SkeletonCard() {
  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-4">
      <Skeleton height="1.5rem" className="w-1/3 mb-4" />
      <Skeleton height="1rem" className="w-full mb-2" />
      <Skeleton height="1rem" className="w-2/3" />
    </div>
  );
}

export function SkeletonTable({ rows = 5 }) {
  return (
    <div className="space-y-3 p-4">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-3 items-center">
          <Skeleton height="1rem" className="w-16" />
          <Skeleton height="1rem" className="flex-1" />
          <Skeleton height="1rem" className="w-24" />
          <Skeleton height="1rem" className="w-20" />
        </div>
      ))}
    </div>
  );
}

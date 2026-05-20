/** Check verde si presente, punto gris si falta */
export default function HeaderCheck({ present, label, points }) {
  if (present) {
    return (
      <span
        className="inline-flex items-center gap-1 text-emerald-600"
        title={`${label} presente${points ? ` (+${points} pts)` : ''}`}
      >
        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
          <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
        </svg>
        <span className="sr-only">{label}</span>
      </span>
    )
  }
  return (
    <span
      className="inline-block w-2 h-2 rounded-full bg-slate-700"
      title={`${label} ausente`}
    />
  )
}

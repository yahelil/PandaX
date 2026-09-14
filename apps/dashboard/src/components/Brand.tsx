import markDark from '../../../landing-page/assets/actis-mark.png'
import markLight from '../../../landing-page/assets/actis-mark-light.png'

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className="brand" aria-label="Actis by PandaX">
      <img className="brand__mark brand__mark--dark" src={markDark} width="42" height="42" alt="" />
      <img className="brand__mark brand__mark--light" src={markLight} width="42" height="42" alt="" />
      {!compact && (
        <span className="brand__name">
          <strong>Actis</strong>
          <small>by PandaX</small>
        </span>
      )}
    </div>
  )
}

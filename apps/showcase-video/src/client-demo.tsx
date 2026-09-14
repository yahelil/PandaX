import React from 'react';
import {AbsoluteFill, Easing, Img, Sequence, interpolate, spring, staticFile, useCurrentFrame, useVideoConfig} from 'remotion';

const clamp = {extrapolateLeft: 'clamp' as const, extrapolateRight: 'clamp' as const};

function Screen({src, scaleTo = 1.012, origin = '50% 42%'}: {src: string; scaleTo?: number; origin?: string}) {
  const frame = useCurrentFrame();
  const {durationInFrames} = useVideoConfig();
  const scale = interpolate(frame, [0, durationInFrames], [1, scaleTo], {...clamp, easing: Easing.inOut(Easing.quad)});
  return <AbsoluteFill style={{overflow: 'hidden', background: '#f5f7fb'}}><Img src={staticFile(`client-demo/${src}`)} style={{width: '100%', height: '100%', objectFit: 'cover', transform: `scale(${scale})`, transformOrigin: origin}} /></AbsoluteFill>;
}

function Cursor({from, to, move, hoverOnly = false}: {from: [number, number]; to: [number, number]; move: [number, number]; hoverOnly?: boolean}) {
  const frame = useCurrentFrame();
  const position = interpolate(frame, move, [0, 1], {...clamp, easing: Easing.inOut(Easing.cubic)});
  const x = interpolate(position, [0, 1], [from[0], to[0]]);
  const y = interpolate(position, [0, 1], [from[1], to[1]]);
  const click = hoverOnly ? 0 : interpolate(frame, [move[1] - 4, move[1], move[1] + 9], [0, 1, 0], clamp);
  return <div style={{position: 'absolute', zIndex: 20, left: x, top: y, filter: 'drop-shadow(0 3px 3px rgba(15,23,32,.24))'}}>
    {!hoverOnly && <div style={{position: 'absolute', width: 26 + click * 30, height: 26 + click * 30, left: -13 - click * 15, top: -13 - click * 15, border: '2px solid #1852c4', borderRadius: '50%', opacity: click * .72}} />}
    <svg width="34" height="42" viewBox="0 0 34 42" aria-hidden="true"><path d="M3 2 30 23l-12 2 8 12-7 4-8-13-8 9Z" fill="#fff" stroke="#0f1720" strokeWidth="2.4" strokeLinejoin="round" /></svg>
  </div>;
}

function UploadShot() {
  const frame = useCurrentFrame();
  return <AbsoluteFill><Screen src={frame >= 43 ? 'upload-hover.png' : 'upload.png'} scaleTo={1.008} origin="58% 58%" /><Cursor from={[1320, 650]} to={[1732, 992]} move={[10, 51]} /></AbsoluteFill>;
}

function FindingShot() {
  const frame = useCurrentFrame();
  const second = [59, 58, 57, 56, 55][Math.min(4, Math.floor(frame / 30))];
  return <Screen src={`finding-${second}.png`} scaleTo={1.01} origin="62% 28%" />;
}

function DocumentsShot() {
  const frame = useCurrentFrame();
  return <AbsoluteFill><Screen src={frame >= 58 ? 'documents-hover.png' : 'documents.png'} scaleTo={1.008} origin="68% 40%" /><Cursor from={[1510, 700]} to={[1772, 448]} move={[22, 66]} hoverOnly /></AbsoluteFill>;
}

function EndCard() {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const enter = spring({fps, frame, config: {damping: 18, stiffness: 82, mass: .9}});
  return <AbsoluteFill style={{background: '#fff', display: 'grid', placeItems: 'center', overflow: 'hidden'}}>
    <div style={{display: 'flex', alignItems: 'center', gap: 54, transform: `translateY(${(1 - enter) * 24}px) scale(${.94 + enter * .06})`, opacity: enter}}>
      <div style={{display: 'flex', alignItems: 'center', gap: 18}}>
        <Img src={staticFile('client-demo/brand/actis-symbol.png')} style={{width: 250, height: 250, objectFit: 'contain', filter: 'contrast(300%) brightness(115%)'}} />
        <Img src={staticFile('client-demo/brand/pandax-symbol.png')} style={{width: 250, height: 250, objectFit: 'contain', filter: 'contrast(300%) brightness(115%)'}} />
      </div>
      <div aria-hidden="true" style={{width: 1, height: 150, background: '#d9e1e8'}} />
      <div style={{fontFamily: 'Archivo, Inter, Segoe UI, sans-serif', color: '#0f1720', fontSize: 104, fontWeight: 720, letterSpacing: '-.055em'}}>Actis</div>
    </div>
  </AbsoluteFill>;
}

export const ActisClientDemo: React.FC = () => <AbsoluteFill style={{background: '#fff'}}>
  <Sequence durationInFrames={60}><Screen src="portfolio.png" scaleTo={1.01} origin="54% 35%" /></Sequence>
  <Sequence from={60} durationInFrames={60}><UploadShot /></Sequence>
  <Sequence from={120} durationInFrames={30}><Screen src="alert.png" scaleTo={1.006} origin="62% 24%" /></Sequence>
  <Sequence from={150} durationInFrames={150}><FindingShot /></Sequence>
  <Sequence from={300} durationInFrames={90}><DocumentsShot /></Sequence>
  <Sequence from={390} durationInFrames={60}><EndCard /></Sequence>
</AbsoluteFill>;

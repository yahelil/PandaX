import React from 'react';
import {AbsoluteFill, Easing, Img, interpolate, spring, staticFile, useCurrentFrame, useVideoConfig} from 'remotion';

const clamp = {extrapolateLeft: 'clamp' as const, extrapolateRight: 'clamp' as const};
const lastFrame = 450;

type LayerProps = {
  start: number;
  end: number;
  src: string;
  hoverSrc?: string;
  hoverAt?: number;
  origin?: string;
};

function DashboardLayer({start, end, src, hoverSrc, hoverAt = Infinity, origin = '58% 36%'}: LayerProps) {
  const frame = useCurrentFrame();
  if (frame < start || frame >= end) return null;
  const enter = start === 0 ? 1 : interpolate(frame, [start, start + 8], [0, 1], {...clamp, easing: Easing.out(Easing.cubic)});
  const exit = end === lastFrame ? 1 : interpolate(frame, [end - 8, end], [1, 0], {...clamp, easing: Easing.in(Easing.cubic)});
  const enterX = start === 0 ? 0 : interpolate(frame, [start, start + 8], [58, 0], clamp);
  const exitX = end === lastFrame ? 0 : interpolate(frame, [end - 8, end], [0, -34], clamp);
  const scale = interpolate(frame, [start, end], [1, 1.005], clamp);
  return <AbsoluteFill style={{opacity: Math.min(enter, exit), transform: `translateX(${enterX + exitX}px)`, overflow: 'hidden', background: '#f5f7fb'}}>
    <Img src={staticFile(`client-demo/${hoverSrc && frame >= hoverAt ? hoverSrc : src}`)} style={{width: '100%', height: '100%', objectFit: 'cover', transform: `scale(${scale})`, transformOrigin: origin}} />
  </AbsoluteFill>;
}

function FindingLayer() {
  const frame = useCurrentFrame();
  if (frame < 191 || frame >= 332) return null;
  const second = frame < 221 ? 59 : frame < 251 ? 58 : frame < 281 ? 57 : 56;
  return <DashboardLayer start={191} end={332} src={`finding-${second}.png`} hoverSrc="finding-documents-hover.png" hoverAt={305} origin="61% 30%" />;
}

const pointerStops = [
  {at: 0, x: 1110, y: 300}, {at: 8, x: 1110, y: 300}, {at: 30, x: 354, y: 480}, {at: 42, x: 354, y: 480},
  {at: 48, x: 430, y: 300}, {at: 67, x: 1750, y: 225}, {at: 80, x: 1750, y: 225},
  {at: 86, x: 1600, y: 330}, {at: 100, x: 1358, y: 474}, {at: 114, x: 1358, y: 474},
  {at: 119, x: 1420, y: 515}, {at: 138, x: 1746, y: 649}, {at: 152, x: 1746, y: 649},
  {at: 159, x: 1720, y: 500}, {at: 178, x: 1758, y: 305}, {at: 193, x: 1758, y: 305},
  {at: 210, x: 1510, y: 330}, {at: 300, x: 714, y: 354}, {at: 324, x: 714, y: 354},
  {at: 335, x: 980, y: 410}, {at: 365, x: 1782, y: 458}, {at: 390, x: 1782, y: 458},
  {at: 415, x: 1640, y: 820}, {at: 450, x: 1640, y: 820},
];
const clickFrames = [36, 75, 110, 147, 188, 319];

function pointerPosition(frame: number) {
  const nextIndex = pointerStops.findIndex((point) => point.at >= frame);
  if (nextIndex <= 0) return pointerStops[0];
  const next = pointerStops[nextIndex];
  const previous = pointerStops[nextIndex - 1];
  const progress = interpolate(frame, [previous.at, next.at], [0, 1], {...clamp, easing: Easing.inOut(Easing.cubic)});
  return {x: interpolate(progress, [0, 1], [previous.x, next.x]), y: interpolate(progress, [0, 1], [previous.y, next.y])};
}

function PersistentCursor() {
  const frame = useCurrentFrame();
  const {x, y} = pointerPosition(frame);
  const press = Math.max(...clickFrames.map((click) => interpolate(frame, [click - 3, click, click + 7], [0, 1, 0], clamp)));
  return <div style={{position: 'absolute', zIndex: 50, left: x, top: y, transform: `scale(${1 - press * .1})`, transformOrigin: '4px 4px', filter: 'drop-shadow(0 3px 3px rgba(15,23,32,.28))'}}>
    <div style={{position: 'absolute', left: -16 - press * 20, top: -16 - press * 20, width: 32 + press * 40, height: 32 + press * 40, border: '3px solid #1852c4', borderRadius: '50%', opacity: press * .78}} />
    <svg width="38" height="46" viewBox="0 0 34 42" aria-hidden="true"><path d="M3 2 30 23l-12 2 8 12-7 4-8-13-8 9Z" fill="#fff" stroke="#0f1720" strokeWidth="2.4" strokeLinejoin="round" /></svg>
  </div>;
}

function AnalyzeTransition() {
  const frame = useCurrentFrame();
  const strength = interpolate(frame, [147, 151, 157], [0, .46, 0], clamp);
  const size = interpolate(frame, [147, 157], [30, 520], clamp);
  if (frame < 147 || frame > 157) return null;
  return <div style={{position: 'absolute', zIndex: 40, left: 1746 - size / 2, top: 649 - size / 2, width: size, height: size, borderRadius: '50%', border: '5px solid #1852c4', background: 'rgba(234,241,255,.5)', opacity: strength}} />;
}

function EndCard() {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const enter = spring({fps, frame: frame - 390, config: {damping: 18, stiffness: 82, mass: .9}});
  if (frame < 390) return null;
  return <AbsoluteFill style={{background: '#fff', display: 'grid', placeItems: 'center', opacity: interpolate(frame, [390, 398], [0, 1], clamp)}}>
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

export const ActisClientDemoV2: React.FC = () => <AbsoluteFill style={{background: '#fff'}}>
  <DashboardLayer start={0} end={47} src="portfolio.png" hoverSrc="portfolio-home-hover.png" hoverAt={30} />
  <DashboardLayer start={39} end={87} src="product.png" hoverSrc="product-register-hover.png" hoverAt={67} origin="64% 27%" />
  <DashboardLayer start={79} end={121} src="upload-empty.png" hoverSrc="upload-empty-hover.png" hoverAt={99} origin="62% 45%" />
  <DashboardLayer start={113} end={157} src="upload-selected.png" hoverSrc="upload-selected-hover.png" hoverAt={134} origin="68% 53%" />
  <DashboardLayer start={149} end={199} src="alert.png" hoverSrc="alert-hover.png" hoverAt={178} origin="66% 27%" />
  <FindingLayer />
  <DashboardLayer start={324} end={398} src="documents.png" hoverSrc="documents-hover.png" hoverAt={364} origin="68% 38%" />
  <EndCard />
  <AnalyzeTransition />
  <PersistentCursor />
</AbsoluteFill>;

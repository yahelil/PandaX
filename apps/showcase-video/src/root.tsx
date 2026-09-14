import React from 'react';
import {Composition} from 'remotion';
import {ActisRealAnalysisDemo} from './showcase';

export const Root: React.FC = () => (
  <Composition
    id="ActisRealAnalysisDemo"
    component={ActisRealAnalysisDemo}
    durationInFrames={1900}
    fps={30}
    width={1920}
    height={1080}
  />
);

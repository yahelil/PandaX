import React from 'react';
import {Composition} from 'remotion';
import {ActisRealAnalysisDemo} from './showcase';
import {ActisClientDemo} from './client-demo';

export const Root: React.FC = () => (
  <>
    <Composition id="ActisRealAnalysisDemo" component={ActisRealAnalysisDemo} durationInFrames={1900} fps={30} width={1920} height={1080} />
    <Composition id="ActisClientDemo" component={ActisClientDemo} durationInFrames={450} fps={30} width={1920} height={1080} />
  </>
);

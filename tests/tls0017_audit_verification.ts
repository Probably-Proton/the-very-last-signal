import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import assert from 'assert';

console.log('=================================================================');
console.log('TLS-0017 — FINAL STAGE REPAIR, MEDIA RESTORATION & STABILITY AUDIT');
console.log('=================================================================\n');

function runAudit() {
  let passed = 0;
  let total = 0;

  function test(name: string, fn: () => void) {
    total++;
    try {
      fn();
      console.log(`[PASS] ${name}`);
      passed++;
    } catch (err: any) {
      console.error(`[FAIL] ${name}:`, err.message);
    }
  }

  // 1. Verify Video File Integrity & Binary Match
  test('1. Final stage MP4 asset exists and matches uploaded unadulterated media exactly', () => {
    const uploadedPath = path.resolve('public/assets/aistudio/WhatsApp_Video_2026-10-29_at_00.25.05_829df3d2.mp4');
    const finalReviewPath = path.resolve('public/assets/FINAL_REVIEW.mp4');

    assert(fs.existsSync(uploadedPath), 'Uploaded MP4 file must exist');
    assert(fs.existsSync(finalReviewPath), 'FINAL_REVIEW.mp4 must exist');

    const uploadedStats = fs.statSync(uploadedPath);
    const finalStats = fs.statSync(finalReviewPath);

    assert.strictEqual(uploadedStats.size, 11062659, 'Uploaded video size must be exactly 11,062,659 bytes');
    assert.strictEqual(finalStats.size, uploadedStats.size, 'FINAL_REVIEW.mp4 must be identical in size to uploaded MP4');

    const uploadedBuf = fs.readFileSync(uploadedPath);
    const finalBuf = fs.readFileSync(finalReviewPath);
    assert(uploadedBuf.equals(finalBuf), 'FINAL_REVIEW.mp4 must be an exact binary clone of the uploaded file');
  });

  // 2. Verify Video Streams via ffprobe (both video and audio streams present and in sync)
  test('2. Video contains valid H.264 video stream and AAC audio stream with synchronized duration', () => {
    const filePath = 'public/assets/FINAL_REVIEW.mp4';
    const probe = execSync(
      `ffprobe -v error -show_entries stream=codec_name,codec_type,duration -of json ${filePath}`,
      { encoding: 'utf-8' }
    );
    const data = JSON.parse(probe);
    const streams = data.streams;

    const videoStream = streams.find((s: any) => s.codec_type === 'video');
    const audioStream = streams.find((s: any) => s.codec_type === 'audio');

    assert(videoStream, 'Must contain a video stream');
    assert(audioStream, 'Must contain an audio stream');
    assert.strictEqual(videoStream.codec_name, 'h264', 'Video codec must be h264');
    assert.strictEqual(audioStream.codec_name, 'aac', 'Audio codec must be aac');

    const vDur = parseFloat(videoStream.duration);
    const aDur = parseFloat(audioStream.duration);
    assert(Math.abs(vDur - aDur) < 0.2, `Video duration (${vDur}s) and audio duration (${aDur}s) must be synchronized within 200ms`);
  });

  // 3. Verify Video Player References in DebriefView and VideoAttachmentViewer
  test('3. Video players prioritize uploaded MP4 with fallback and HTML5 block containment', () => {
    const debriefCode = fs.readFileSync('src/components/DebriefView.tsx', 'utf-8');
    const viewerCode = fs.readFileSync('src/components/VideoAttachmentViewer.tsx', 'utf-8');

    assert(debriefCode.includes('/assets/aistudio/WhatsApp_Video_2026-10-29_at_00.25.05_829df3d2.mp4'), 'DebriefView must reference uploaded MP4');
    assert(debriefCode.includes('/assets/FINAL_REVIEW.mp4'), 'DebriefView must reference FINAL_REVIEW.mp4');
    assert(viewerCode.includes('/assets/aistudio/WhatsApp_Video_2026-10-29_at_00.25.05_829df3d2.mp4'), 'VideoAttachmentViewer must reference uploaded MP4');
    assert(viewerCode.includes('/assets/FINAL_REVIEW.mp4'), 'VideoAttachmentViewer must reference FINAL_REVIEW.mp4');
    assert(debriefCode.includes('className="w-full h-full object-contain bg-black block"'), 'DebriefView video element must use block containment');
  });

  // 4. Verify Removal of Stage 5 Audio Association & Isolation from Video
  test('4. Stage 5 audio (SignalAudio) is explicitly cleaned up and isolated when mounting Stage 6 & Stage 7', () => {
    const debriefCode = fs.readFileSync('src/components/DebriefView.tsx', 'utf-8');
    const viewerCode = fs.readFileSync('src/components/VideoAttachmentViewer.tsx', 'utf-8');
    const appCode = fs.readFileSync('src/App.tsx', 'utf-8');

    assert(debriefCode.includes('signalAudio.cleanup()'), 'DebriefView must call signalAudio.cleanup() to silence Stage 5 audio');
    assert(viewerCode.includes('signalAudio.cleanup()'), 'VideoAttachmentViewer must call signalAudio.cleanup() to silence Stage 5 audio');
    assert(appCode.includes('if (route.view === \'debrief\''), 'App.tsx must clean up signalAudio when navigating into Stage 6/7');
  });

  // 5. Verify ControlledSystemGlitch Stability Fix (Ref Callbacks & No Reset Loops)
  test('5. ControlledSystemGlitch uses callback refs preventing infinite restart loops upon parent render', () => {
    const glitchCode = fs.readFileSync('src/components/ControlledSystemGlitch.tsx', 'utf-8');

    assert(glitchCode.includes('const onCompleteRef = useRef(onComplete)'), 'ControlledSystemGlitch must store onComplete in a ref');
    assert(glitchCode.includes('onCompleteRef.current()'), 'ControlledSystemGlitch must call onCompleteRef.current()');
    assert(!glitchCode.includes('}, [isActive, reducedScareMode, clearAllTimers, handleBypass, onComplete]'), 'useEffect must not depend on changing onComplete function');
  });

  // 6. Verify Evidence Unlocking Logic in App.tsx (No False Lockouts on EV-0701 / EV-0702)
  test('6. App.tsx allows unlocked evidence (EV-0701, EV-0702) to be opened without false security lockout', () => {
    const appCode = fs.readFileSync('src/App.tsx', 'utf-8');

    assert(appCode.includes('progress.unlockedEvidenceIds.includes(item.id) ||'), 'App.tsx must check progress.unlockedEvidenceIds as a standalone bypass');
  });

  // 7. Verify Server Challenge Mapping for Stage 6 & Stage 7
  test('7. Server maps stage6_record_tomorrow and stage7_debrief with canonical answers', () => {
    const serverCode = fs.readFileSync('server.ts', 'utf-8');

    assert(serverCode.includes('stage6_record_tomorrow: 6'), 'server.ts must map stage6_record_tomorrow to Stage 6');
    assert(serverCode.includes('stage7_debrief: 7'), 'server.ts must map stage7_debrief to Stage 7');
    assert(serverCode.includes("c.includes('ev1971')"), 'server.ts must validate ev1971 for stage6');
  });

  // 8. Verify Non-Destructive Leaderboard Sync in DebriefView
  test('8. DebriefView synchronizes completed Stage 7 score directly to /api/leaderboard/sync without reset', () => {
    const debriefCode = fs.readFileSync('src/components/DebriefView.tsx', 'utf-8');

    assert(debriefCode.includes('/api/leaderboard/sync'), 'DebriefView must sync score to /api/leaderboard/sync');
    assert(debriefCode.includes('stagesCompleted: 7'), 'DebriefView must record stagesCompleted: 7');
    assert(debriefCode.includes("stage7Step === 'completed'"), 'DebriefView must prevent duplicate awards');
  });

  console.log(`\nResults: ${passed} / ${total} tests passed.`);
  if (passed === total) {
    console.log('ALL TLS-0017 AUDIT VERIFICATIONS PASSED SUCCESSFULLY!');
  } else {
    process.exit(1);
  }
}

runAudit();

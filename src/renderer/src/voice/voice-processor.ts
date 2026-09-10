// src/renderer/src/voice/voice-processor.ts

/**
 * VoiceProcessor implements a basic audio processing pipeline that applies:
 *   - High-pass filter (85 Hz) to remove rumble
 *   - Low-pass filter (7500 Hz) to remove high-frequency hiss
 *   - Optional noise-gate (dynamic gain reduction based on RMS level)
 *   - Provides an AnalyserNode for VU-meter visualisation
 *
 * The processor can be used for real calls and for the "ouvir o microfone"
 * test loopback. All nodes are exposed so the caller can connect them to the
 * desired destination.
 */
export interface VoiceProcessorOptions {
  /** Enable the internal noise‑gate (mute when signal below threshold) */
  noiseGateEnabled?: boolean;
  /** RMS threshold (0‑1) where the gate opens – lower = more sensitive */
  gateThreshold?: number;
  /** Attack time in seconds for the gate (how fast it opens) */
  attack?: number;
  /** Release time in seconds for the gate (how fast it closes) */
  release?: number;
}

export class VoiceProcessor {
  private audioCtx: AudioContext;
  private sourceNode!: MediaStreamAudioSourceNode;
  private highPass: BiquadFilterNode;
  private lowPass: BiquadFilterNode;
  private gainNode: GainNode; // acts as noise‑gate (gain 0/1)
  private analyser: AnalyserNode;

  private noiseGateEnabled: boolean;
  private gateThreshold: number;
  private attack: number;
  private release: number;

  // Internal state for gate smoothing
  private lastGain = 1;

  constructor(audioCtx: AudioContext, options?: VoiceProcessorOptions) {
    this.audioCtx = audioCtx;
    this.noiseGateEnabled = options?.noiseGateEnabled ?? false;
    this.gateThreshold = options?.gateThreshold ?? 0.03; // ~3% RMS
    this.attack = options?.attack ?? 0.02;
    this.release = options?.release ?? 0.1;

    // High‑pass – cut rumble and sub‑audio
    this.highPass = audioCtx.createBiquadFilter();
    this.highPass.type = 'highpass';
    this.highPass.frequency.value = 85;

    // Low‑pass – limit to voice band
    this.lowPass = audioCtx.createBiquadFilter();
    this.lowPass.type = 'lowpass';
    this.lowPass.frequency.value = 7500;

    // Gain acts as noise‑gate
    this.gainNode = audioCtx.createGain();
    this.gainNode.gain.value = 1;

    // Analyser for VU‑meter
    this.analyser = audioCtx.createAnalyser();
    this.analyser.fftSize = 256;
    this.analyser.smoothingTimeConstant = 0.2;

    // Chain will be built after source is attached
  }

  /** Attach a MediaStream (microphone) as the source */
  attachSource(stream: MediaStream) {
    if (this.sourceNode) {
      this.sourceNode.disconnect();
    }
    this.sourceNode = this.audioCtx.createMediaStreamSource(stream);
    // source → highPass → lowPass → gainNode
    this.sourceNode.connect(this.highPass);
    this.highPass.connect(this.lowPass);
    this.lowPass.connect(this.gainNode);
    // branch to analyser for visual feedback
    this.gainNode.connect(this.analyser);
  }

  /** Output node that should be routed to the final destination */
  getOutputNode(): GainNode {
    return this.gainNode;
  }

  /** Analyser node for VU‑meter */
  getAnalyserNode(): AnalyserNode {
    return this.analyser;
  }

  /** Enable/disable noise‑gate at runtime */
  setNoiseGate(enabled: boolean) {
    this.noiseGateEnabled = enabled;
  }

  /** Adjust gate threshold (0-1) */
  setGateThreshold(threshold: number) {
    this.gateThreshold = threshold;
  }

  /** Adjust noise gate sensitivity by percentage (1% to 100%) */
  setLevel(percent: number) {
    const clamped = Math.max(1, Math.min(100, percent));
    // 1% = 0.003 (suave), 50% = ~0.03 (equilibrado), 100% = 0.10 (agressivo)
    this.gateThreshold = 0.003 + ((clamped - 1) / 99) * 0.097;
  }

  getGateThreshold(): number {
    return this.gateThreshold;
  }

  /** Called repeatedly (e.g., in a requestAnimationFrame loop) to update the gate */
  updateGate() {
    if (!this.noiseGateEnabled) {
      if (this.gainNode.gain.value !== 1) {
        this.gainNode.gain.setTargetAtTime(1, this.audioCtx.currentTime, this.attack);
      }
      return;
    }
    const data = new Uint8Array(this.analyser.frequencyBinCount);
    this.analyser.getByteFrequencyData(data);
    let sum = 0;
    for (let i = 0; i < data.length; i++) sum += data[i] ?? 0;
    const rms = sum / (data.length * 255);
    const target = rms > this.gateThreshold ? 1 : 0;
    const timeConst = target > this.lastGain ? this.attack : this.release;
    this.gainNode.gain.setTargetAtTime(target, this.audioCtx.currentTime, timeConst);
    this.lastGain = target;
  }
}

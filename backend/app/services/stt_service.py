import os
import io
import wave
import struct
import math
import re
import logging
from groq import AsyncGroq

logger = logging.getLogger("satrk.stt")

HALLUCINATION_PATTERNS = [
    r'^(you\s*)+$',
    r'^(thank\s*you\s*\.?\s*)+$',
    r'subtitles?\s*by',
    r'amara\.org',
    r'mbc\s*news',
    r'subscribe',
    r'thanks\s*for\s*watching',
    r'bye\s*bye',
    r'^\.+$',
    r'^\?+$'
]


def create_wav_bytes(pcm_bytes: bytes, sample_rate: int = 16000, num_channels: int = 1, sample_width: int = 2) -> bytes:
    """
    Wraps raw PCM 16-bit audio bytes in a standard 44-byte WAV container.
    """
    buf = io.BytesIO()
    with wave.open(buf, 'wb') as wav_file:
        wav_file.setnchannels(num_channels)
        wav_file.setsampwidth(sample_width)
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(pcm_bytes)
    return buf.getvalue()


def is_pcm_silent(pcm_bytes: bytes, threshold_rms: float = 10.0) -> bool:
    """
    Calculates RMS (Root Mean Square) energy of raw PCM 16-bit audio buffer.
    Returns True if audio energy is below threshold (dead-air / silent room).
    """
    if not pcm_bytes or len(pcm_bytes) < 4:
        logger.info(f"Audio chunk empty or too small ({len(pcm_bytes)} bytes) -> Discarding")
        return True
    try:
        count = len(pcm_bytes) // 2
        shorts = struct.unpack(f"<{count}h", pcm_bytes[:count * 2])
        sum_squares = sum(float(s) * float(s) for s in shorts)
        rms = math.sqrt(sum_squares / count)
        is_silent = rms < threshold_rms
        logger.info(f"Audio Chunk RMS: {rms:.2f} (Threshold: {threshold_rms}) -> Discarding: {is_silent}")
        return is_silent
    except Exception as e:
        logger.warning(f"Error computing PCM RMS: {e}")
        return False


def filter_hallucinations(text: str) -> str:
    """
    Filters out Whisper hallucination loops (e.g. 'you you you', 'thank you. thank you.')
    and common Whisper subtitle artifacts.
    """
    if not text:
        return ""

    cleaned = text.strip()
    lower_text = cleaned.lower()

    # 1. Check regex hallucination artifacts
    for pattern in HALLUCINATION_PATTERNS:
        if re.search(pattern, lower_text):
            logger.info(f"Filtered Whisper hallucination pattern '{pattern}' from text: '{cleaned}'")
            return ""

    # 2. Check token repetition ratio (e.g., "you you you", "the the the")
    words = [w.strip(".,!?\"'") for w in lower_text.split() if w.strip(".,!?\"'")]
    if len(words) >= 2:
        word_counts = {}
        for w in words:
            word_counts[w] = word_counts.get(w, 0) + 1
        most_frequent_count = max(word_counts.values())
        if most_frequent_count / len(words) >= 0.6 and len(words) >= 3:
            logger.info(f"Filtered repetitive token loop ({most_frequent_count}/{len(words)}) from text: '{cleaned}'")
            return ""

    return cleaned


class STTService:
    def __init__(self, api_key: str = None):
        self.client = AsyncGroq(api_key=api_key or os.environ.get("GROQ_API_KEY"))

    async def transcribe_audio(self, audio_bytes: bytes, filename: str = "audio.webm") -> str:
        """
        Transcribes/translates audio bytes to English text via Groq Whisper API (translations endpoint, temperature=0.0).
        Supports Indian languages (Hindi, Marathi, Gujarati, etc.) directly into English.
        Includes energy pre-filtering and repetition loop post-filtering.
        """
        if not audio_bytes or len(audio_bytes) < 100:
            return ""

        try:
            is_raw_pcm = False

            # Detect media format by magic bytes
            if audio_bytes.startswith(b'\x1a\x45\xdf\xa3'):
                target_filename = "audio.webm"
                target_bytes = audio_bytes
            elif audio_bytes.startswith(b'OggS'):
                target_filename = "audio.ogg"
                target_bytes = audio_bytes
            elif audio_bytes.startswith(b'RIFF'):
                target_filename = "audio.wav"
                target_bytes = audio_bytes
            elif audio_bytes.startswith(b'ftyp') or (len(audio_bytes) > 8 and audio_bytes[4:8] == b'ftyp'):
                target_filename = "audio.mp4"
                target_bytes = audio_bytes
            else:
                # Raw PCM 16-bit 16kHz audio from Android AudioRecord
                is_raw_pcm = True
                if is_pcm_silent(audio_bytes, threshold_rms=10.0):
                    return ""
                target_filename = "audio.wav"
                target_bytes = create_wav_bytes(audio_bytes, sample_rate=16000, num_channels=1, sample_width=2)

            file_tuple = (target_filename, target_bytes)
            response = await self.client.audio.translations.create(
                file=file_tuple,
                model="whisper-large-v3",
                temperature=0.0,
                response_format="text"
            )

            raw_text = ""
            if isinstance(response, str):
                raw_text = response.strip()
            elif isinstance(response, dict):
                raw_text = response.get("text", "").strip()

            logger.info(f"Groq Whisper Raw STT Output: '{raw_text}'")

            filtered_text = filter_hallucinations(raw_text)
            if raw_text and not filtered_text:
                logger.info(f"STT Text '{raw_text}' was discarded by hallucination filter.")
            elif filtered_text:
                logger.info(f"Final Validated STT Transcript: '{filtered_text}'")

            return filtered_text

        except Exception as e:
            logger.warning(f"STT Service transcription skipped invalid chunk: {e}")
            return ""
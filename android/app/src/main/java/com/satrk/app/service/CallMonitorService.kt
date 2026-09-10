package com.satrk.app.service

import android.annotation.SuppressLint
import android.app.*
import android.content.Context
import android.content.Intent
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.Build
import android.os.IBinder
import android.telephony.PhoneStateListener
import android.telephony.TelephonyCallback
import android.telephony.TelephonyManager
import android.util.Log
import androidx.core.app.NotificationCompat
import com.satrk.app.network.CallAnalysisCallback
import com.satrk.app.network.CallAnalysisResult
import com.satrk.app.network.CallWebSocketClient
import java.util.concurrent.atomic.AtomicBoolean

class CallMonitorService : Service(), CallAnalysisCallback {

    private var webSocketClient: CallWebSocketClient? = null
    private var audioRecord: AudioRecord? = null
    private var recordingThread: Thread? = null
    private val isRecording = AtomicBoolean(false)

    private var serverIp: String = CallWebSocketClient.DEFAULT_SERVER_IP
    private var serverPort: Int = 8000
    private var callId: String = ""

    private var telephonyManager: TelephonyManager? = null
    private var telephonyCallback: TelephonyCallback? = null

    private var currentAudioSource: Int = MediaRecorder.AudioSource.VOICE_CALL

    @Suppress("DEPRECATION")
    private val legacyPhoneStateListener = object : PhoneStateListener() {
        @Deprecated("Deprecated in Java")
        override fun onCallStateChanged(state: Int, incomingNumber: String?) {
            handleCallStateChange(state)
        }
    }

    companion object {
        private const val TAG = "CallMonitorService"
        private const val CHANNEL_ID = "SatrkCallMonitorChannel"
        private const val NOTIFICATION_ID = 1001

        const val ACTION_START_MONITORING = "com.satrk.app.action.START_MONITORING"
        const val ACTION_STOP_MONITORING = "com.satrk.app.action.STOP_MONITORING"
        const val ACTION_STATUS_UPDATE = "com.satrk.app.action.STATUS_UPDATE"
        const val EXTRA_SERVER_IP = "extra_server_ip"
        const val EXTRA_SERVER_PORT = "extra_server_port"
        const val EXTRA_CALL_ID = "extra_call_id"
        const val EXTRA_STATUS = "extra_status"

        const val STATUS_CONNECTED = "CONNECTED"
        const val STATUS_DISCONNECTED = "DISCONNECTED"
        const val STATUS_ERROR = "ERROR"

        const val SAMPLE_RATE = 16000
        const val CHANNEL_CONFIG = AudioFormat.CHANNEL_IN_MONO
        const val AUDIO_FORMAT = AudioFormat.ENCODING_PCM_16BIT
    }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "CallMonitorService Created.")
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) return START_NOT_STICKY

        when (intent.action) {
            ACTION_START_MONITORING -> {
                serverIp = intent.getStringExtra(EXTRA_SERVER_IP) ?: CallWebSocketClient.DEFAULT_SERVER_IP
                serverPort = intent.getIntExtra(EXTRA_SERVER_PORT, 8000)
                callId = intent.getStringExtra(EXTRA_CALL_ID) ?: "call_${System.currentTimeMillis()}"

                Log.i(TAG, "Starting call monitoring service for callId: $callId, target: $serverIp:$serverPort")
                startForegroundServiceNotification("Satrk Shield Standby", "Waiting for active phone call...")
                registerPhoneStateListener()
            }
            ACTION_STOP_MONITORING -> {
                Log.i(TAG, "Stopping call monitoring service via Intent...")
                stopSelf()
            }
        }

        return START_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Satrk Call Protection Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Monitors live call audio in background for digital arrest scam detection."
            }
            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun startForegroundServiceNotification(title: String, text: String) {
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_btn_speak_now)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

        startForeground(NOTIFICATION_ID, notification)
    }

    private fun updateNotificationAlert(result: CallAnalysisResult) {
        if (result.isAlert) {
            val alertNotification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("⚠️ CRITICAL SCAM ALERT DETECTED!")
                .setContentText("Risk Score: ${result.riskScore.toInt()}% - ${result.hits.joinToString()}")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setVibrate(longArrayOf(0, 500, 200, 500))
                .build()

            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.notify(NOTIFICATION_ID, alertNotification)
        }
    }

    private fun registerPhoneStateListener() {
        telephonyManager = getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        if (telephonyManager == null) {
            Log.e(TAG, "TelephonyManager is null! Falling back to direct monitoring.")
            startMonitoring()
            return
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val callback = object : TelephonyCallback(), TelephonyCallback.CallStateListener {
                    override fun onCallStateChanged(state: Int) {
                        handleCallStateChange(state)
                    }
                }
                telephonyCallback = callback
                telephonyManager?.registerTelephonyCallback(mainExecutor, callback)
            } else {
                @Suppress("DEPRECATION")
                telephonyManager?.listen(legacyPhoneStateListener, PhoneStateListener.LISTEN_CALL_STATE)
            }
            Log.i(TAG, "Telephony call state listener registered successfully.")

            // Check if call is already offhook at registration time
            val currentState = telephonyManager?.callState ?: TelephonyManager.CALL_STATE_IDLE
            Log.i(TAG, "Initial Telephony callState: $currentState")
            if (currentState == TelephonyManager.CALL_STATE_OFFHOOK) {
                handleCallStateChange(TelephonyManager.CALL_STATE_OFFHOOK)
            }
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException registering TelephonyListener (missing READ_PHONE_STATE permission?): ${e.message}")
            startMonitoring()
        } catch (e: Exception) {
            Log.e(TAG, "Error registering TelephonyListener: ${e.message}", e)
            startMonitoring()
        }
    }

    private fun unregisterPhoneStateListener() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                telephonyCallback?.let {
                    telephonyManager?.unregisterTelephonyCallback(it)
                }
                telephonyCallback = null
            } else {
                @Suppress("DEPRECATION")
                telephonyManager?.listen(legacyPhoneStateListener, PhoneStateListener.LISTEN_NONE)
            }
            Log.i(TAG, "Telephony call state listener unregistered.")
        } catch (e: Exception) {
            Log.e(TAG, "Error unregistering TelephonyListener: ${e.message}")
        }
    }

    private fun handleCallStateChange(state: Int) {
        when (state) {
            TelephonyManager.CALL_STATE_OFFHOOK -> {
                Log.i(TAG, "Telephony call state: OFFHOOK (Active call detected!) -> Starting audio recording & WS connection.")
                startForegroundServiceNotification("Satrk Call Shield Active", "Recording & analyzing active call audio live...")
                startMonitoring()
            }
            TelephonyManager.CALL_STATE_IDLE -> {
                Log.i(TAG, "Telephony call state: IDLE (Call ended or inactive) -> Stopping audio recording & WS connection.")
                startForegroundServiceNotification("Satrk Shield Standby", "Call ended. Waiting for next phone call...")
                stopMonitoring()
            }
            TelephonyManager.CALL_STATE_RINGING -> {
                Log.i(TAG, "Telephony call state: RINGING (Incoming phone call ringing...)")
                startForegroundServiceNotification("Satrk Call Shield Ringing", "Incoming call ringing...")
            }
        }
    }

    private fun getSourceName(source: Int): String {
        return when (source) {
            MediaRecorder.AudioSource.VOICE_CALL -> "VOICE_CALL"
            MediaRecorder.AudioSource.VOICE_COMMUNICATION -> "VOICE_COMMUNICATION"
            MediaRecorder.AudioSource.VOICE_RECOGNITION -> "VOICE_RECOGNITION"
            MediaRecorder.AudioSource.MIC -> "MIC"
            else -> "Source($source)"
        }
    }

    private fun calculateMaxAmplitude(buffer: ByteArray, bytesRead: Int): Int {
        var maxVal = 0
        var i = 0
        while (i < bytesRead - 1) {
            val sample = (buffer[i].toInt() and 0xFF) or (buffer[i + 1].toInt() shl 8)
            val shortSample = sample.toShort()
            val absVal = kotlin.math.abs(shortSample.toInt())
            if (absVal > maxVal) {
                maxVal = absVal
            }
            i += 2
        }
        return maxVal
    }

    @SuppressLint("MissingPermission")
    private fun switchAudioSourceFallback(bufferSize: Int) {
        val nextSource = when (currentAudioSource) {
            MediaRecorder.AudioSource.VOICE_CALL -> MediaRecorder.AudioSource.VOICE_COMMUNICATION
            MediaRecorder.AudioSource.VOICE_COMMUNICATION -> MediaRecorder.AudioSource.MIC
            else -> MediaRecorder.AudioSource.MIC
        }

        Log.w(TAG, "AUTOMATIC AUDIO FALLBACK: Source ${getSourceName(currentAudioSource)} is producing zeroed/silent audio. Switching to ${getSourceName(nextSource)}...")

        try {
            if (audioRecord?.state == AudioRecord.STATE_INITIALIZED) {
                audioRecord?.stop()
            }
            audioRecord?.release()
            audioRecord = null
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping current AudioRecord during fallback: ${e.message}")
        }

        try {
            val candidate = AudioRecord(
                nextSource,
                SAMPLE_RATE,
                CHANNEL_CONFIG,
                AUDIO_FORMAT,
                bufferSize
            )
            if (candidate.state == AudioRecord.STATE_INITIALIZED) {
                audioRecord = candidate
                currentAudioSource = nextSource
                audioRecord?.startRecording()
                Log.i(TAG, "Successfully fallback-switched AudioRecord source to ${getSourceName(currentAudioSource)}")
            } else {
                candidate.release()
                // Final fallback to MIC
                val micCandidate = AudioRecord(
                    MediaRecorder.AudioSource.MIC,
                    SAMPLE_RATE,
                    CHANNEL_CONFIG,
                    AUDIO_FORMAT,
                    bufferSize
                )
                if (micCandidate.state == AudioRecord.STATE_INITIALIZED) {
                    audioRecord = micCandidate
                    currentAudioSource = MediaRecorder.AudioSource.MIC
                    audioRecord?.startRecording()
                    Log.i(TAG, "Successfully fallback-switched AudioRecord source to MIC")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to switch AudioRecord source to ${getSourceName(nextSource)}: ${e.message}", e)
        }
    }

    @SuppressLint("MissingPermission")
    private fun startMonitoring() {
        if (isRecording.get()) {
            Log.w(TAG, "Call monitoring is already running.")
            return
        }

        // Initialize WebSocket Client
        webSocketClient = CallWebSocketClient()
        webSocketClient?.connect(serverIp, serverPort, callId, this)

        // Initialize AudioRecord with call-optimized audio sources fallback
        val minBufferSize = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL_CONFIG, AUDIO_FORMAT)
        val bufferSize = maxOf(minBufferSize, SAMPLE_RATE * 2 * 2) // 2 seconds buffer chunks

        val audioSourcesToTry = intArrayOf(
            MediaRecorder.AudioSource.VOICE_CALL,
            MediaRecorder.AudioSource.VOICE_COMMUNICATION,
            MediaRecorder.AudioSource.VOICE_RECOGNITION,
            MediaRecorder.AudioSource.MIC
        )

        var record: AudioRecord? = null

        for (source in audioSourcesToTry) {
            try {
                val candidate = AudioRecord(
                    source,
                    SAMPLE_RATE,
                    CHANNEL_CONFIG,
                    AUDIO_FORMAT,
                    bufferSize
                )
                if (candidate.state == AudioRecord.STATE_INITIALIZED) {
                    record = candidate
                    currentAudioSource = source
                    Log.i(TAG, "AudioRecord successfully initialized with source: ${getSourceName(currentAudioSource)}")
                    break
                } else {
                    candidate.release()
                }
            } catch (e: Exception) {
                Log.w(TAG, "AudioRecord initialization failed for source ${getSourceName(source)}: ${e.message}")
            }
        }

        if (record == null) {
            Log.e(TAG, "AudioRecord initialization failed for all available audio sources!")
            sendStatusBroadcast(STATUS_ERROR)
            return
        }

        audioRecord = record
        try {
            audioRecord?.startRecording()
            isRecording.set(true)

            // Background worker thread for audio buffer streaming
            recordingThread = Thread({
                val audioBuffer = ByteArray(bufferSize)
                Log.i(TAG, "Audio recording thread started using source ${getSourceName(currentAudioSource)}. Buffer size: $bufferSize bytes.")
                var consecutiveSilentChunks = 0

                while (isRecording.get()) {
                    val bytesRead = audioRecord?.read(audioBuffer, 0, audioBuffer.size) ?: 0
                    if (bytesRead > 0) {
                        val maxAmp = calculateMaxAmplitude(audioBuffer, bytesRead)
                        
                        if (maxAmp < 15) {
                            consecutiveSilentChunks++
                            Log.w(TAG, "Audio read max amplitude: $maxAmp (Zero/Silent chunk #$consecutiveSilentChunks with source ${getSourceName(currentAudioSource)})")
                            
                            // If current source is producing 3 consecutive zeroed/silent chunks and is not MIC, fallback!
                            if (consecutiveSilentChunks >= 3 && currentAudioSource != MediaRecorder.AudioSource.MIC) {
                                switchAudioSourceFallback(bufferSize)
                                consecutiveSilentChunks = 0
                                continue
                            }
                        } else {
                            consecutiveSilentChunks = 0
                            Log.d(TAG, "Captured active audio chunk (maxAmp=$maxAmp, source=${getSourceName(currentAudioSource)})")
                        }

                        val chunk = if (bytesRead == audioBuffer.size) audioBuffer else audioBuffer.copyOf(bytesRead)
                        webSocketClient?.sendAudioChunk(chunk)
                    } else {
                        Log.w(TAG, "AudioRecord read returned non-positive value: $bytesRead")
                    }
                }
                Log.i(TAG, "Audio recording loop finished.")
            }, "SatrkAudioRecorderThread")

            recordingThread?.start()

        } catch (e: Exception) {
            Log.e(TAG, "Error starting AudioRecord recording: ${e.message}", e)
        }
    }

    private fun stopMonitoring() {
        if (!isRecording.get()) {
            Log.i(TAG, "stopMonitoring called but recording is not active.")
            return
        }

        Log.i(TAG, "Stopping audio recording & WebSocket stream...")
        isRecording.set(false)

        try {
            recordingThread?.interrupt()
            recordingThread = null
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping recording thread: ${e.message}")
        }

        try {
            if (audioRecord?.state == AudioRecord.STATE_INITIALIZED) {
                audioRecord?.stop()
            }
            audioRecord?.release()
            audioRecord = null
        } catch (e: Exception) {
            Log.e(TAG, "Error releasing AudioRecord: ${e.message}")
        }

        webSocketClient?.disconnect()
        webSocketClient = null

        sendStatusBroadcast(STATUS_DISCONNECTED)
    }

    override fun onConnected() {
        Log.i(TAG, "Call Monitoring WebSocket connected successfully to server!")
        sendStatusBroadcast(STATUS_CONNECTED)
    }

    override fun onAnalysisReceived(result: CallAnalysisResult) {
        Log.i(TAG, "Analysis Update -> Risk: ${result.riskScore}%, Alert: ${result.isAlert}, Transcript: ${result.transcript}")
        updateNotificationAlert(result)
    }

    override fun onError(error: String) {
        Log.e(TAG, "Call Monitoring WebSocket Error: $error")
        sendStatusBroadcast(STATUS_ERROR)
    }

    override fun onClosed() {
        Log.i(TAG, "Call Monitoring WebSocket Closed.")
        sendStatusBroadcast(STATUS_DISCONNECTED)
    }

    override fun onDestroy() {
        Log.i(TAG, "Tearing down CallMonitorService...")
        unregisterPhoneStateListener()
        stopMonitoring()
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    private fun sendStatusBroadcast(status: String) {
        val intent = Intent(ACTION_STATUS_UPDATE)
        intent.putExtra(EXTRA_STATUS, status)
        sendBroadcast(intent)
    }

    override fun onBind(intent: Intent?): IBinder? = null
}

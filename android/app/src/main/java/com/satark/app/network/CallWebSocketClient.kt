package com.satark.app.network

import android.util.Log
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.json.JSONObject
import java.util.concurrent.TimeUnit

data class CallAnalysisResult(
    val callId: String?,
    val latestChunk: String?,
    val transcript: String,
    val riskScore: Double,
    val isAlert: Boolean,
    val hits: List<String>
)

interface CallAnalysisCallback {
    fun onAnalysisReceived(result: CallAnalysisResult)
    fun onError(error: String)
    fun onClosed()
}

class CallWebSocketClient {

    private var webSocket: WebSocket? = null
    private var client: OkHttpClient? = null
    private var callback: CallAnalysisCallback? = null

    companion object {
        private const val TAG = "CallWebSocketClient"
        const val DEFAULT_SERVER_IP = "10.57.107.249"
    }

    fun connect(serverIp: String = DEFAULT_SERVER_IP, port: Int = 8000, callId: String, callback: CallAnalysisCallback) {
        this.callback = callback

        client = OkHttpClient.Builder()
            .readTimeout(10, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .connectTimeout(10, TimeUnit.SECONDS)
            .build()

        val url = "ws://$serverIp:$port/calls/ws/$callId"
        Log.i(TAG, "Connecting to WebSocket: $url")

        val request = Request.Builder()
            .url(url)
            .build()

        webSocket = client?.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.i(TAG, "WebSocket connected successfully to $url")
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                Log.d(TAG, "Received JSON message: $text")
                try {
                    val json = JSONObject(text)
                    val hitsArray = json.optJSONArray("hits")
                    val hitsList = mutableListOf<String>()
                    if (hitsArray != null) {
                        for (i in 0 until hitsArray.length()) {
                            hitsList.add(hitsArray.getString(i))
                        }
                    }

                    val result = CallAnalysisResult(
                        callId = json.optString("call_id"),
                        latestChunk = json.optString("latest_chunk"),
                        transcript = json.optString("transcript", ""),
                        riskScore = json.optDouble("risk_score", 0.0),
                        isAlert = json.optBoolean("alert", false),
                        hits = hitsList
                    )

                    this@CallWebSocketClient.callback?.onAnalysisReceived(result)

                } catch (e: Exception) {
                    Log.e(TAG, "Error parsing WebSocket JSON payload: ${e.message}", e)
                    this@CallWebSocketClient.callback?.onError("Failed to parse JSON response: ${e.message}")
                }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                Log.d(TAG, "Received binary message of size: ${bytes.size}")
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.e(TAG, "WebSocket failure: ${t.message}", t)
                this@CallWebSocketClient.callback?.onError("WebSocket connection failed: ${t.message}")
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.i(TAG, "WebSocket closed: $code / $reason")
                this@CallWebSocketClient.callback?.onClosed()
            }
        })
    }

    fun sendAudioChunk(audioBytes: ByteArray) {
        if (webSocket != null) {
            val byteString = audioBytes.toByteString(0, audioBytes.size)
            val success = webSocket?.send(byteString) ?: false
            if (!success) {
                Log.w(TAG, "Failed to send audio chunk byteString over WebSocket.")
            }
        } else {
            Log.w(TAG, "Cannot send audio chunk. WebSocket is null/disconnected.")
        }
    }

    fun disconnect() {
        Log.i(TAG, "Disconnecting WebSocket...")
        webSocket?.close(1000, "Client initiated disconnection")
        webSocket = null
        client?.dispatcher?.executorService?.shutdown()
        client = null
        callback = null
    }
}

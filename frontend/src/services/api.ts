import axios from 'axios';

let customApiBaseUrl: string | null = null;

/**
 * Set a dynamic runtime API base URL override.
 */
export const setRuntimeApiBaseUrl = (url: string) => {
    customApiBaseUrl = url.replace(/\/$/, '');
};

/**
 * Dynamically determine the API base URL.
 * Priority:
 * 1. Explicit runtime override set via setRuntimeApiBaseUrl()
 * 2. Environment variable import.meta.env.VITE_API_BASE_URL
 * 3. Dynamic browser origin hostname (allowing local network / mobile access)
 * 4. Fallback to http://127.0.0.1:8000
 */
export const getApiBaseUrl = (): string => {
    if (customApiBaseUrl) {
        return customApiBaseUrl;
    }
    const envUrl = import.meta.env?.VITE_API_BASE_URL;
    if (envUrl && typeof envUrl === 'string' && envUrl.trim() !== '') {
        return envUrl.trim().replace(/\/$/, '');
    }
    if (typeof window !== 'undefined' && window.location?.hostname) {
        const protocol = window.location.protocol || 'http:';
        const hostname = window.location.hostname;
        return `${protocol}//${hostname}:8000`;
    }
    return "http://127.0.0.1:8000";
};

export const API_BASE_URL = getApiBaseUrl();

export const scanTextMessage = async (message: string) => {
    try {
        const baseUrl = getApiBaseUrl();
        const response = await axios.post(`${baseUrl}/api/analyze`, { message, text: message });
        return response.data;
    } catch (error: any) {
        return { success: false, error: error.response?.data?.detail || error.message || "Failed to connect to backend" };
    }
};

export const scanImageMessage = async (file: File) => {
    try {
        const baseUrl = getApiBaseUrl();
        const formData = new FormData();
        formData.append("file", file);
        const response = await axios.post(`${baseUrl}/api/v1/analyze/image`, formData, {
            headers: { "Content-Type": "multipart/form-data" }
        });
        return response.data;
    } catch (error: any) {
        return { success: false, error: error.response?.data?.detail || error.message || "Image vision scan failed" };
    }
};

export const uploadCallFrame = async (callId: string, file: File) => {
    try {
        const baseUrl = getApiBaseUrl();
        const formData = new FormData();
        formData.append("file", file);
        const response = await axios.post(`${baseUrl}/calls/frame/${callId}`, formData, {
            headers: { "Content-Type": "multipart/form-data" }
        });
        return { success: true, data: response.data };
    } catch (error: any) {
        return {
            success: false,
            error: error.response?.data?.detail || error.message || "Frame upload failed"
        };
    }
};

export const uploadAudioFile = async (file: File) => {
    try {
        const baseUrl = getApiBaseUrl();
        const formData = new FormData();
        formData.append("file", file);
        const response = await axios.post(`${baseUrl}/calls/upload-audio`, formData, {
            headers: { "Content-Type": "multipart/form-data" }
        });
        return { success: true, data: response.data };
    } catch (error: any) {
        return { 
            success: false, 
            error: error.response?.data?.detail || error.message || "Audio file upload failed" 
        };
    }
};

export interface LinkAnalysisResult {
    url: string;
    is_safe: boolean;
    threat_types: string[];
    details: string;
}

export const analyzeLink = async (url: string) => {
    const baseUrl = getApiBaseUrl();
    const fullUrl = `${baseUrl}/api/v1/analyze/link`;
    try {
        console.log(`[api.ts] Sending POST request to analyzeLink at: ${fullUrl}`, { url });
        const response = await axios.post(fullUrl, { url }, {
            headers: { 'Content-Type': 'application/json' }
        });
        return { success: true, data: response.data as LinkAnalysisResult };
    } catch (error: any) {
        console.error(`[api.ts] analyzeLink failed at ${fullUrl}:`, error);
        let detailedMsg = "Link analysis failed";
        if (axios.isAxiosError(error)) {
            console.error('[api.ts] Axios Error Details:', {
                message: error.message,
                code: error.code,
                status: error.response?.status,
                data: error.response?.data,
                configUrl: error.config?.url,
            });
            if (error.response?.data?.detail) {
                detailedMsg = typeof error.response.data.detail === 'string'
                    ? error.response.data.detail
                    : JSON.stringify(error.response.data.detail);
            } else if (error.code === 'ERR_NETWORK' || error.message === 'Network Error') {
                detailedMsg = `Network Error: Unable to reach backend server at ${fullUrl}. Please verify that Uvicorn backend is running on port 8000.`;
            } else {
                detailedMsg = `API Error (${error.code || error.response?.status || 'Unknown'}): ${error.message}`;
            }
        } else if (error.message) {
            detailedMsg = error.message;
        }
        return {
            success: false,
            error: detailedMsg
        };
    }
};

export const submitFeedback = async (callId: string, alertWasCorrect: boolean, transcriptSnippet: string) => {
    const baseUrl = getApiBaseUrl();
    const fullUrl = `${baseUrl}/api/v1/feedback`;
    try {
        console.log(`[api.ts] Sending POST request to submitFeedback at: ${fullUrl}`);
        const response = await axios.post(fullUrl, {
            call_id: callId,
            alert_was_correct: alertWasCorrect,
            transcript_snippet: transcriptSnippet
        }, {
            headers: { 'Content-Type': 'application/json' }
        });
        return { success: true, data: response.data };
    } catch (error: any) {
        console.error(`[api.ts] submitFeedback failed at ${fullUrl}:`, error);
        let detailedMsg = "Feedback submission failed";
        if (axios.isAxiosError(error)) {
            console.error('[api.ts] Axios Error Details:', {
                message: error.message,
                code: error.code,
                status: error.response?.status,
                data: error.response?.data,
                configUrl: error.config?.url,
            });
            if (error.response?.data?.detail) {
                detailedMsg = typeof error.response.data.detail === 'string'
                    ? error.response.data.detail
                    : JSON.stringify(error.response.data.detail);
            } else if (error.code === 'ERR_NETWORK' || error.message === 'Network Error') {
                detailedMsg = `Network Error: Unable to reach backend server at ${fullUrl}.`;
            } else {
                detailedMsg = `API Error (${error.code || error.response?.status || 'Unknown'}): ${error.message}`;
            }
        } else if (error.message) {
            detailedMsg = error.message;
        }
        return {
            success: false,
            error: detailedMsg
        };
    }
};
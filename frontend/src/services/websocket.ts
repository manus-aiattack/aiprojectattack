// WebSocket service - socket.io-client temporarily disabled
// To enable: npm install socket.io-client

// import { io, Socket } from 'socket.io-client';

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

class WebSocketService {
  // private socket: Socket | null = null;
  private listeners: Map<string, Set<Function>> = new Map();

  connect() {
    console.log('[WebSocket] Service disabled - install socket.io-client to enable');
    // Stub implementation - does nothing
    /*
    if (this.socket?.connected) {
      return;
    }

    const token = localStorage.getItem('auth_token');

    this.socket = io(WS_URL, {
      auth: {
        token,
      },
      transports: ['websocket'],
    });

    this.socket.on('connect', () => {
      console.log('[WebSocket] Connected');
    });

    this.socket.on('disconnect', () => {
      console.log('[WebSocket] Disconnected');
    });

    this.socket.on('error', (error) => {
      console.error('[WebSocket] Error:', error);
    });
    */
  }

  disconnect() {
    console.log('[WebSocket] Service disabled');
    /*
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    this.listeners.clear();
    */
  }

  on(event: string, callback: Function) {
    console.log(`[WebSocket] Listener registered for ${event} (disabled)`);
    /*
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(callback);

    if (this.socket) {
      this.socket.on(event, (...args) => {
        callback(...args);
      });
    }
    */
  }

  off(event: string, callback?: Function) {
    console.log(`[WebSocket] Listener removed for ${event} (disabled)`);
    /*
    if (callback) {
      this.listeners.get(event)?.delete(callback);
      if (this.socket) {
        this.socket.off(event, callback as any);
      }
    } else {
      this.listeners.delete(event);
      if (this.socket) {
        this.socket.off(event);
      }
    }
    */
  }

  emit(event: string, data?: any) {
    console.log(`[WebSocket] Emit ${event} (disabled)`, data);
    /*
    if (this.socket) {
      this.socket.emit(event, data);
    }
    */
  }
}

export const wsService = new WebSocketService();


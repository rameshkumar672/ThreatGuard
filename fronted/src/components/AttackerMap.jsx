import React from 'react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { motion } from 'framer-motion';
import { Globe2, Activity } from 'lucide-react';

const createHackerIcon = (severity) => {
    const colorClass = severity.toLowerCase();
    
    const html = `
        <div class="hacker-marker-container text-${colorClass}">
            <div class="radar-ring"></div>
            <div class="radar-ring radar-ring-2"></div>
            <div class="radar-ring radar-ring-3"></div>
            <div class="marker-core bg-${colorClass}">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                    <path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8z"/>
                    <circle cx="12" cy="12" r="3"/>
                </svg>
            </div>
        </div>
    `;

    return L.divIcon({
        className: 'custom-hacker-icon',
        html: html,
        iconSize: [40, 40],
        iconAnchor: [20, 20]
    });
};

const AttackerMap = ({ attacks = [] }) => {
    const center = [20, 0];
    const zoom = 2;

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="cyber-card p-6 h-[600px] flex flex-col relative"
        >
            <div className="flex justify-between items-center mb-4 border-b border-cyber-600 pb-3">
                <h3 className="text-xl font-bold font-mono text-white flex items-center gap-2">
                    <Activity className="text-cyber-danger w-5 h-5 animate-pulse" />
                    SYSTEM_THREAT_MAP
                </h3>
                <div className="flex gap-4 text-[10px] font-mono">
                    <span className="flex items-center gap-1 text-critical"><span className="w-2 h-2 rounded-full bg-critical animate-ping"></span> CRITICAL</span>
                    <span className="flex items-center gap-1 text-high"><span className="w-2 h-2 rounded-full bg-high"></span> HIGH</span>
                    <span className="flex items-center gap-1 text-medium"><span className="w-2 h-2 rounded-full bg-medium"></span> MEDIUM</span>
                </div>
            </div>

            <div className="flex-1 rounded border border-cyber-600 overflow-hidden relative z-0">
                <MapContainer 
                    center={center} 
                    zoom={zoom} 
                    style={{ height: '100%', width: '100%', background: '#060B14' }}
                    scrollWheelZoom={true}
                    attributionControl={false}
                >
                    <TileLayer
                        url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                    />
                    
                    {attacks.map((attack, idx) => {
                        if (!attack.latitude || !attack.longitude) return null;
                        
                        const colorClass = attack.severity.toLowerCase();

                        return (
                            <Marker 
                                key={attack._id || idx} 
                                position={[attack.latitude, attack.longitude]}
                                icon={createHackerIcon(attack.severity)}
                            >
                                <Popup 
                                    className={`cyber-hacker-popup border-${colorClass}`}
                                    autoClose={false}
                                    closeOnClick={false}
                                    closeButton={false}
                                    permanent={true}
                                >
                                    <div className="hacker-alert-container">
                                        <div className={`hacker-alert-header bg-${colorClass}`}>
                                            <span>Threat Detected</span>
                                            <span>● LIVE</span>
                                        </div>
                                        <div className="hacker-alert-body">
                                            <div className="mb-1">
                                                <span className="hacker-label">TYPE:</span>
                                                <span className={`hacker-value text-${colorClass}`}>{attack.attackType}</span>
                                            </div>
                                            <div className="mb-1">
                                                <span className="hacker-label">SEVERITY:</span>
                                                <span className={`hacker-value text-${colorClass}`}>{attack.severity}</span>
                                            </div>
                                            <div className="mb-1">
                                                <span className="hacker-label">IP_ADDR:</span>
                                                <span className="hacker-value text-white">{attack.ip}</span>
                                            </div>
                                            <div className="mb-1">
                                                <span className="hacker-label">LOCATION:</span>
                                                <span className="hacker-value text-white">{attack.city}, {attack.state ? `${attack.state}, ` : ''}{attack.country}</span>
                                            </div>
                                            <div className="mb-1">
                                                <span className="hacker-label">ISP_NODE:</span>
                                                <span className="hacker-value text-gray-400 text-[9px]">{attack.isp || 'UNKNOWN'}</span>
                                            </div>
                                            <div className="mb-1">
                                                <span className="hacker-label">STATUS:</span>
                                                <span className="hacker-value text-cyber-success">ACTIVE_SCAN</span>
                                            </div>
                                            <div className="mt-2 text-[9px] text-gray-500 border-t border-gray-800 pt-1">
                                                TIMESTAMP: {new Date(attack.createdAt).toLocaleTimeString()}
                                            </div>
                                        </div>
                                    </div>
                                </Popup>
                            </Marker>
                        );
                    })}
                </MapContainer>
            </div>
            
            {/* Scanline Overlay */}
            <div className="absolute inset-0 pointer-events-none opacity-[0.05] bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%]"></div>
        </motion.div>
    );
};

export default AttackerMap;

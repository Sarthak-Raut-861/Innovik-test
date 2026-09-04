/**
 * @trustpulse/sdk - Mouse Kinematic Feature Extraction
 *
 * Derives statistical kinematics (velocities, accelerations, angular curvature)
 * from locally sampled trajectory points. Never transmits coordinate points.
 */
import { MathUtils } from "../utils/Math";
export class MouseFeatureExtractor {
    static extract(samples) {
        if (!samples || samples.length < 2) {
            return {
                sampleCount: samples ? samples.length : 0,
                meanVelocity: 0,
                velocityStdDev: 0,
                meanAcceleration: 0,
                directionChangeRate: 0,
                movementDuration: 0,
                totalDistance: 0,
            };
        }
        const velocities = [];
        const accelerations = [];
        const angleDeltas = [];
        let totalDist = 0;
        let totalDuration = samples[samples.length - 1].timestamp - samples[0].timestamp;
        if (totalDuration <= 0)
            totalDuration = 1;
        for (let i = 1; i < samples.length; i++) {
            const prev = samples[i - 1];
            const curr = samples[i];
            const dt = (curr.timestamp - prev.timestamp) / 1000; // in seconds
            if (dt <= 0)
                continue;
            const dist = MathUtils.euclideanDistance(prev.x, prev.y, curr.x, curr.y);
            totalDist += dist;
            const v = dist / dt; // px/sec
            velocities.push(v);
            if (velocities.length >= 2) {
                const prevV = velocities[velocities.length - 2];
                const dv = v - prevV;
                const a = Math.abs(dv / dt); // px/sec^2
                accelerations.push(a);
            }
            if (i >= 2) {
                const p0 = samples[i - 2];
                const dx1 = prev.x - p0.x;
                const dy1 = prev.y - p0.y;
                const dx2 = curr.x - prev.x;
                const dy2 = curr.y - prev.y;
                const angle = MathUtils.angleDelta(dx1, dy1, dx2, dy2);
                angleDeltas.push(angle);
            }
        }
        const meanV = MathUtils.mean(velocities);
        const vStd = MathUtils.stdDev(velocities, meanV);
        const meanA = MathUtils.mean(accelerations);
        // Direction change rate: radians per second of motion
        const totalAngle = angleDeltas.reduce((acc, curr) => acc + curr, 0);
        const dirRate = totalDuration > 0 ? (totalAngle / (totalDuration / 1000)) : 0;
        return {
            sampleCount: samples.length,
            meanVelocity: MathUtils.safeNumber(meanV, 0, 50000),
            velocityStdDev: MathUtils.safeNumber(vStd, 0, 50000),
            meanAcceleration: MathUtils.safeNumber(meanA, 0, 500000),
            directionChangeRate: MathUtils.safeNumber(dirRate, 0, 100),
            movementDuration: MathUtils.safeNumber(totalDuration, 0, 60000),
            totalDistance: MathUtils.safeNumber(totalDist, 0, 1000000),
        };
    }
}
//# sourceMappingURL=MouseFeatures.js.map
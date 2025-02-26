package edu.rit.croatia.swen383.g2.ws.sensor;

import java.util.Random;

/**
 * PressureSensor provides pressure readings in inHg (inches of mercury).
 * Raw reading are provided that can be converted to other pressure units.
 */
public class PressureSensor implements Sensor {
  // Constants for pressure reading limits in hundreths of inHg
  private static final int MINREADING = 2800; // 28.00 inHg
  private static final int MAXREADING = 3200; // 32.00 inHg
  private static final int DEFAULT = 3000; // 30.00 inHg

  private int currentReading; // Current pressure reading
  private boolean increasing; // Pressure trend direction
  private Random rand; // For simulating changes

  /**
   * Creates a new PressureSensor with default reading.
   */
  public PressureSensor() {
    currentReading = DEFAULT;
    increasing = true;
    rand = new Random();
  }

  /**
   * Reads current pressure valu with simulated fluctuations.
   * Raw reading is in hundredths of inHg which can be converted to
   * other units (inHg, mbar) using MeasurementUnit conversions.
   */
  @Override
  public int read() {
    final double CUTOFF = 0.8; // 80% chance to continue trend
    final int MAXCHANGE = 20; // Max change in hundredths
    final int MINCHANGE = 5; // Min change in hundredths

    // Determine if pressure trend should change
    if (rand.nextDouble() > CUTOFF) {
      increasing = !increasing;
    }

    // Calculate pressure change
    int change = rand.nextInt(MAXCHANGE - MINCHANGE) + MINCHANGE;
    currentReading += change * (increasing ? 1 : -1);

    // Enforce pressure bounds
    if (currentReading >= MAXREADING) {
      currentReading = MAXREADING;
      increasing = false;
    } else if (currentReading <= MINREADING) {
      currentReading = MINREADING;
      increasing = true;
    }

    return currentReading;
  }
}

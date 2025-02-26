package edu.rit.croatia.swen383.g2.ws.sensor;


import java.util.Random; // to simulate random temperature fluctuations.

/**
 * Class for a (simulated) sensor of temperature.
 */
public class TemperatureSensor implements Sensor{
  private static final int MINREADING = 23315; // -40 C
  private static final int MAXREADING = 32315; // 50 C
  private static final int DEFAULT = 29315; // 20 C

  private int currentReading;
  private boolean increasing;
  private Random rand;

  /*
   * Constructs a new TemperatureSensor initialzied to the default temperature.
   */
  public TemperatureSensor() {
    currentReading = DEFAULT;
    increasing = true;
    rand = new Random();
  }

  /*
   * Reads the current temperature value with simulated fluctuations.
   *
   * @return The current temperature reading in 1/100ths of a Kelvin
   */
  public int read() {
    final double CUTOFF = 0.8; // 80% chance to continue trend
    final int MAXCHANGE = 200; // maximum change in 1/100ths degree
    final int MINCHANGE = 100; // minimum change in 1/100ths degree

    // Determine if temperature trend should change
    if (rand.nextDouble() > CUTOFF) {
      increasing = !increasing;
    }

    // Calculate temperature change
    int tempChange = rand.nextInt(MAXCHANGE - MINCHANGE) + MINCHANGE;
    currentReading += tempChange * (increasing ? 1 : -1);

    // Enforce temperature bounds
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

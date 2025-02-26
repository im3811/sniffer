package edu.rit.croatia.swen383.g2.ws.ui;

import edu.rit.croatia.swen383.g2.ws.WeatherStation;
import edu.rit.croatia.swen383.g2.ws.observer.Observer;
import edu.rit.croatia.swen383.g2.ws.util.MeasurementUnit;

public class TextUI implements Observer {
  private final WeatherStation station;

  public TextUI(WeatherStation station) { this.station = station; }

  @Override
  public void update() {
    System.out.println("\nCurrent readings:");
    System.out.println("Temperature:");
    System.out.println(
        "KELVIN: " +
        String.format("%.2f", station.getReading(MeasurementUnit.KELVIN)));
    System.out.println(
        "CELSIUS: " +
        String.format("%.2f", station.getReading(MeasurementUnit.CELSIUS)));
    System.out.println(
        "FAHRENHEIT: " +
        String.format("%.2f", station.getReading(MeasurementUnit.FAHRENHEIT)));

    System.out.println("\nPressure:");
    System.out.println(
        "INHG: " +
        String.format("%.2f", station.getReading(MeasurementUnit.INHG)));
    System.out.println(
        "MBAR: " +
        String.format("%.2f", station.getReading(MeasurementUnit.MBAR)));
  }
}

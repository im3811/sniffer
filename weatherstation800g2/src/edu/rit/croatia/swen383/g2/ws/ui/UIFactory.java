package edu.rit.croatia.swen383.g2.ws.ui;

import edu.rit.croatia.swen383.g2.ws.WeatherStation;
import edu.rit.croatia.swen383.g2.ws.observer.Observer;

public class UIFactory {
  private final WeatherStation station;

  public UIFactory(WeatherStation station) { this.station = station; }

  public Observer getUI(String type) {
    return switch (type.toLowerCase()) {
      case "text" -> new TextUI(station);
      case "swing" -> new SwingUI(station);
      case "javafx" -> new JavaFXUI(station);
      case "statistics" -> new StatisticsDisplay(station);
      case "forecast" -> new ForcastDisplay(station);
      default -> throw new IllegalArgumentException("Invalid UI type: " + type);
    };
  }
}

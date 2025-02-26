package edu.rit.croatia.swen383.g2.ws;

import edu.rit.croatia.swen383.g2.ws.observer.Observer;
import edu.rit.croatia.swen383.g2.ws.ui.UIFactory;

public class WeatherStationRunner {
  public static void main(String[] args) {
    // Create the WeatherStation (the "Subject")
    WeatherStation station = new WeatherStation();

    // Create the UIFactory
    UIFactory uiFactory = new UIFactory(station);

    // Calling getUI() for each UI type
    Observer textUI = uiFactory.getUI("text");
    Observer swingUI = uiFactory.getUI("swing");
    Observer javafxUI = uiFactory.getUI("javafx");
    Observer statsUI = uiFactory.getUI("statistics");
    Observer forecastUI = uiFactory.getUI("forecast");

    // Attach all UI components to the WeatherStation
    station.attach(textUI);
    station.attach(swingUI);
    station.attach(javafxUI);
    station.attach(statsUI);
    station.attach(forecastUI);

    System.out.println(
        "\nStarting Weather Station with all UI components...\n");
    station.run();
  }
}

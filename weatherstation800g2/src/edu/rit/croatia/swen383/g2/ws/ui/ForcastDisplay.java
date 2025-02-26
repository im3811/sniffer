package edu.rit.croatia.swen383.g2.ws.ui;
import edu.rit.croatia.swen383.g2.ws.WeatherStation;
import edu.rit.croatia.swen383.g2.ws.observer.Observer;
import edu.rit.croatia.swen383.g2.ws.util.MeasurementUnit;

public class ForcastDisplay implements Observer {
    private final WeatherStation station;
    
    public ForcastDisplay(WeatherStation station) {
        this.station = station;
    }
    
    @Override
    public void update() {
        double tempCelsius = station.getReading(MeasurementUnit.CELSIUS);
        double pressureMbar = station.getReading(MeasurementUnit.MBAR);
        
        System.out.println("\nWeather Forecast:");
        System.out.println("Temperature (Celsius): " + tempCelsius + "°C");
        System.out.println("Pressure (Millibars): " + pressureMbar + " mbar");
    }
}


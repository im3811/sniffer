
package edu.rit.croatia.swen383.g2.ws.util;
import java.util.List;
import java.util.Arrays;


public enum MeasurementUnit {
    KELVIN(SensorType.TEMPERATURE, 1.0, 0.0), CELSIUS(SensorType.TEMPERATURE, 1.0, -27315.0), 
    FAHRENHEIT(SensorType.TEMPERATURE, 1.8, -45967.0),

    INHG(SensorType.PRESSURE, 1.0, 0.0), MBAR(SensorType.PRESSURE, 33.864, 0.0);

    private final SensorType type;
    private final double cf1;
    private final double cf2;

    MeasurementUnit(SensorType type, double cf1, double cf2) {
        this.type = type;
        this.cf1 = cf1;
        this.cf2 = cf2;
    }

    public double get(int reading){
        return (reading * cf1 + cf2) / 100.0;
    }


    public static List<MeasurementUnit> valuesOf(SensorType sensorType){
        return Arrays.stream(values())
            .filter(unit -> unit.type == sensorType)
            .toList();
    }
}
package edu.rit.croatia.swen383.g2.ws.sensor;

import edu.rit.croatia.swen383.g2.ws.util.SensorType;
import java.util.EnumMap;

public class SensorFactory {
  private final EnumMap<SensorType, Sensor> sensors;

  public SensorFactory() {
    sensors = new EnumMap<>(SensorType.class);
    createSensors();
  }

  private void createSensors() {
    sensors.put(SensorType.TEMPERATURE, new TemperatureSensor());
    sensors.put(SensorType.PRESSURE, new PressureSensor());
  }

  public Sensor getSensor(SensorType type) {
    return switch (type) {
      case TEMPERATURE -> sensors.get(SensorType.TEMPERATURE);
      case PRESSURE -> sensors.get(SensorType.PRESSURE);
    };
  }

  public int readSensorType(SensorType type) {
    Sensor sensor = getSensor(type);
    return (sensor != null) ? sensor.read() :
        0;
      }
  }

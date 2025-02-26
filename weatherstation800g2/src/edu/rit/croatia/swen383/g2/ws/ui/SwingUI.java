package edu.rit.croatia.swen383.g2.ws.ui;

import edu.rit.croatia.swen383.g2.ws.WeatherStation;
import edu.rit.croatia.swen383.g2.ws.observer.Observer;
import edu.rit.croatia.swen383.g2.ws.util.MeasurementUnit;
import edu.rit.croatia.swen383.g2.ws.util.SensorType;
import java.awt.*;
import java.util.EnumMap;
import javax.swing.*;

public class SwingUI implements Observer {
  private final WeatherStation station;
  private EnumMap<MeasurementUnit, JLabel> labelMap;
  private Font labelFont;

  public SwingUI(WeatherStation station) {
    this.station = station;
    this.labelMap = new EnumMap<>(MeasurementUnit.class);
    setupUI();
  }

  private void setupUI() {
    JFrame frame = new JFrame("Weather Station");
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    JPanel mainPanel = new JPanel(new GridLayout(2, 1, 10, 10));
    mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

    JPanel tempPanel = new JPanel(new GridLayout(1, 3, 5, 5));
    for (MeasurementUnit unit :
         MeasurementUnit.valuesOf(SensorType.TEMPERATURE)) {
      tempPanel.add(createPanel(unit));
    }

    JPanel pressurePanel = new JPanel(new GridLayout(1, 2, 5, 5));
    for (MeasurementUnit unit : MeasurementUnit.valuesOf(SensorType.PRESSURE)) {
      pressurePanel.add(createPanel(unit));
    }

    mainPanel.add(tempPanel);
    mainPanel.add(pressurePanel);
    frame.add(mainPanel);
    frame.pack();
    frame.setLocationRelativeTo(null);
    frame.setVisible(true);
  }

  private JLabel createLabel(String title) {
    JLabel label = new JLabel(title, SwingConstants.CENTER);
    label.setFont(new Font("Arial", Font.BOLD, 24));
    return label;
  }

  private JPanel createPanel(MeasurementUnit unit) {
    JPanel panel = new JPanel(new BorderLayout(5, 5));
    panel.setBorder(BorderFactory.createEtchedBorder());
    panel.add(createLabel(unit.toString()), BorderLayout.NORTH);
    JLabel valueLabel = new JLabel("--", SwingConstants.CENTER);
    valueLabel.setFont(new Font("Arial", Font.PLAIN, 24));
    labelMap.put(unit, valueLabel);
    panel.add(valueLabel, BorderLayout.CENTER);
    return panel;
  }

  private void setLabel(MeasurementUnit unit, double value) {
    JLabel label = labelMap.get(unit);
    if (label != null) {
      label.setText(String.format("%.2f", value));
    }
  }

  @Override
  public void update() {
    SwingUtilities.invokeLater(() -> {
      for (MeasurementUnit unit : MeasurementUnit.values()) {
        setLabel(unit, station.getReading(unit));
      }
    });
  }
}

package edu.rit.croatia.swen383.g2.ws.ui;

/**
 * JavaFXUI is a JavaFX application that displays temperature readings in both
 * Celsius and Kelvin formats. It provides a simple UI with labels to show
 * temperature values and allows updating them dynamically.
 */
import edu.rit.croatia.swen383.g2.ws.WeatherStation;
import edu.rit.croatia.swen383.g2.ws.observer.Observer;
import edu.rit.croatia.swen383.g2.ws.util.MeasurementUnit;
import edu.rit.croatia.swen383.g2.ws.util.SensorType;
import java.util.EnumMap;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

public class JavaFXUI extends Application implements Observer {
  private final WeatherStation station;
  private EnumMap<MeasurementUnit, Label> labelMap;
  private static JavaFXUI instance;
  private Stage stage;

  public JavaFXUI(WeatherStation station) {
    this.station = station;
    labelMap = new EnumMap<>(MeasurementUnit.class);
    instance = this;
    Platform.startup(() -> {
      stage = new Stage();
      setupUI(stage);
    });
  }

  private void setupUI(Stage primaryStage) {
    primaryStage.setTitle("Weather Station");
    VBox mainBox = new VBox(20);
    mainBox.setAlignment(Pos.CENTER);

    VBox tempDisplay = new VBox(10);
    tempDisplay.setAlignment(Pos.CENTER);
    HBox tempBox = new HBox(20);
    tempBox.setAlignment(Pos.CENTER);
    Label tempTitle = new Label("Temperature");
    tempTitle.setStyle("-fx-font-size: 20px; -fx-font-weight: bold");

    for (MeasurementUnit unit :
         MeasurementUnit.valuesOf(SensorType.TEMPERATURE)) {
      tempBox.getChildren().add(createTemperatureDisplay(unit.toString()));
    }

    tempDisplay.getChildren().addAll(tempTitle, tempBox);

    VBox pressureDisplay = new VBox(10);
    pressureDisplay.setAlignment(Pos.CENTER);
    HBox pressureBox = new HBox(20);
    pressureBox.setAlignment(Pos.CENTER);
    Label pressureTitle = new Label("Pressure");
    pressureTitle.setStyle("-fx-font-size: 20px; -fx-font-weight: bold;");

    for (MeasurementUnit unit : MeasurementUnit.valuesOf(SensorType.PRESSURE)) {
      pressureBox.getChildren().add(createTemperatureDisplay(unit.toString()));
    }

    pressureDisplay.getChildren().addAll(pressureTitle, pressureBox);

    mainBox.getChildren().addAll(tempDisplay, pressureDisplay);
    Scene scene = new Scene(mainBox, 600, 400);
    primaryStage.setScene(scene);
    primaryStage.show();
  }

  @Override
  public void start(Stage primaryStage) {}

  public VBox createTemperatureDisplay(String title) {
    Label titleLabel = new Label(title);
    titleLabel.setStyle("-fx-font-size: 16px; -fx-font-weight: bold;");
    Label valueLabel = new Label("--");
    valueLabel.setStyle("-fx-font-size: 14px");
    labelMap.put(MeasurementUnit.valueOf(title), valueLabel);
    VBox display = new VBox(5);
    display.setAlignment(Pos.CENTER);
    display.getChildren().addAll(titleLabel, valueLabel);
    return display;
  }

  public void update() {
    Platform.runLater(() -> {
      for (MeasurementUnit unit : MeasurementUnit.values()) {
        Label label = labelMap.get(unit);
        if (label != null) {
          label.setText(String.format("%.2f", station.getReading(unit)));
        }
      }
    });
  }
}

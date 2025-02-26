package edu.rit.croatia.swen383.g2.ws.observer;

import java.util.List;
import java.util.ArrayList;

public class Subject {
  private List<Observer> observers;

  public Subject() {
    observers = new ArrayList<>();
  }

  public void attach(Observer observer) {
    observers.add(observer);

  }

  public void detach(Observer observer) {
    observers.remove(observer);
  }

  public void notifyObservers() {
    for (Observer observer : observers) {
      observer.update();
    }
  }
}

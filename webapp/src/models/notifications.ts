export class CustomNotification {
  public kind!: "custom";
}

export class ProgressNotification {
  public kind!: "progress";
  public maxProgress = 0;
  public currentProgress = 0;
  public message = "";

  get taskWidthPercentage() {
    let percentage = (this.currentProgress / this.maxProgress) * 100.0;
    if (isNaN(percentage) || percentage < 0) {
      percentage = 0;
    } else if (percentage > 100) {
      percentage = 100;
    }
    return {
      width: `${percentage}%`
    };
  }
}

export type Notification = ProgressNotification | CustomNotification;

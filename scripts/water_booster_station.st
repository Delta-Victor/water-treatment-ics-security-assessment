PROGRAM WaterBoosterStation
  VAR
    cycle_counter : INT := 0;
  END_VAR

  VAR
    pump_running AT %QX0.0 : BOOL := TRUE;
    high_pressure_alarm AT %QX0.1 : BOOL := FALSE;
    chlorine_dosing AT %QX0.2 : BOOL := TRUE;
    system_pressure AT %QW0 : INT := 65;
  END_VAR

  cycle_counter := cycle_counter + 1;
  IF cycle_counter >= 100 THEN
    cycle_counter := 0;
  END_IF;

  IF pump_running = TRUE THEN
    IF system_pressure < 80 THEN
      system_pressure := system_pressure + 1;
    END_IF;
  ELSE
    IF system_pressure > 0 THEN
      system_pressure := system_pressure - 2;
    END_IF;
  END_IF;

  IF system_pressure > 75 THEN
    high_pressure_alarm := TRUE;
  ELSE
    high_pressure_alarm := FALSE;
  END_IF;

END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#100ms, PRIORITY := 0);
    PROGRAM inst0 WITH task0 : WaterBoosterStation;
  END_RESOURCE
END_CONFIGURATION
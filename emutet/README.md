
# Usage

```
python emutet.py -h
Usage: emutet.py [options]

Options:
  -h, --help            show this help message and exit
  -c CAPE, --cape=CAPE  Analysis ID from https://www.capesandbox.com
  -t TRIAGE, --triage=TRIAGE
                        Analysis ID from https://www.tria.ge
  -k TRIAGE_API_KEY, --triage-api-key=TRIAGE_API_KEY
                        Triage API key file. To get yours go to
                        https://tria.ge and ask for an account
  -o OUTPUT, --output=OUTPUT
                        Output directory
  -v, --verbose         Verbose mode. Shows errors and debugging prints
  -T, --try-all         Try all C&C in the C&C list. By default the bot will
                        stop oncea sucess response is gotten from the C&C.
                        This can be when it downloads new modules or when the
                        C&C response is empty. If this option is enabled the
                        bot doesn't stop until all C&C responses are checked

```

**IMPORTANT:** Be patient. Not always it works on the first try. As it's explained in the [documentation](../README.md) each time the bot is executed a random bot_id is created. Perhaps that the C&C doesn't allow that bot_id or at the moment the C&C is down for the country you are connected from. Try more times, connect from other country and/or also add new entries into config files. New names, surnames, processes... 

## Example using Triage (Anaysis: https://tria.ge/reports/191017-kla4z5rz3x/task1)
It downloads new modules + Trickbot sample
[![asciicast](https://asciinema.org/a/275991.png)](https://asciinema.org/a/275991)

## Example using CAPE (Analysis: https://www.capesandbox.com/analysis/4102/)
It Downloads new modules
[![asciicast](https://asciinema.org/a/275749.png)](https://asciinema.org/a/275749)

## More Examples

  1. `python emutet.py -T --triage 191018-294pp5srbn --triage-api-key {triage-api-key-file}`
  2. `python emutet.py -T --triage 191018-294pp5srbn` (default Triage api key file location is used `./config/triage-api-key.txt`)
  3. `python emutet.py -T --cape 4010`
  4. `python emutet.py --cape 4010` this case the `-T` option is missing. This means that once a sucess response is returned from the list of C&Cs the bot stops, the rest of the C&C won't be checked. 
  5. `python emutet.py -v -T --cape 4010` verbose mode.

# Firewall Audit Tool

The Firewall Audit Tool is designed to help network administrators and security professionals audit firewall configurations. It parses device configuration files that describe firewall rules, address objects, service objects, and address groups. The tool checks for security issues and sub optimal configuration such as duplicates or rules that may be overly permissive, and generates reports on these findings to assist in the optimization and hardening of firewall configurations.

## System Design

![Project Design](static/Firewall_analyzer.png)

## Usage

```python main.py --input input_config_1.xml input_config_2.xml --platform paloalto.panos --report excel```


## Running Tests
Firewall Audit Tool comes with a suite of tests to ensure the reliability of its features. To run these tests, use the following command:

```pytest```

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

tba

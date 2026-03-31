
if __name__ == "__main__":

    builder = SimulationBuilder(config_path="config.json")

    result = builder.run()

    print(result)
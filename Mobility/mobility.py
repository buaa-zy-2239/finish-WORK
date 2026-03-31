from ns import ns


class MobilityFactory:

    # =========================
    # 通用入口
    # =========================

    @staticmethod
    def install(node, mobility_conf):

        mtype = mobility_conf["type"]

        if mtype == "waypoint":
            MobilityFactory._install_waypoint(
                node,
                mobility_conf["waypoints"]
            )

        elif mtype == "random":
            MobilityFactory._install_random(node)

        else:
            raise ValueError(f"Unknown mobility type: {mtype}")

    # =========================
    # Waypoint
    # =========================

    @staticmethod
    def _install_waypoint(node, waypoints):

        helper = ns.MobilityHelper()
        helper.SetMobilityModel("ns3::WaypointMobilityModel")

        container = ns.NodeContainer()
        container.Add(node)

        helper.Install(container)

        mobility = node.GetObject[ns.WaypointMobilityModel]()

        for t, pos in waypoints:

            mobility.AddWaypoint(
                ns.Waypoint(
                    ns.Seconds(t),
                    ns.Vector(pos[0], pos[1], pos[2])
                )
            )

    # =========================
    # Random
    # =========================

    @staticmethod
    def _install_random(node):

        helper = ns.MobilityHelper()

        helper.SetMobilityModel(
            "ns3::RandomWalk2dMobilityModel",
            "Bounds", ns.RectangleValue(ns.Rectangle(-500, 500, -500, 500))
        )

        container = ns.NodeContainer()
        container.Add(node)

        helper.Install(container)

    # =========================
    # ZSP固定位置
    # =========================

    @staticmethod
    def install_constant(node, pos):

        helper = ns.MobilityHelper()

        helper.SetMobilityModel("ns3::ConstantPositionMobilityModel")

        container = ns.NodeContainer()
        container.Add(node)

        helper.Install(container)

        mobility = node.GetObject[ns.MobilityModel]()

        mobility.SetPosition(
            ns.Vector(pos[0], pos[1], pos[2])
        )
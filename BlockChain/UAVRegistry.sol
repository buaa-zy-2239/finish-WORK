// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UAVRegistry {

    struct UAVInfo {
        bool registered;
        bool blacklisted;
        uint256 regTime;
    }

    // PID -> UAVInfo
    mapping(bytes32 => UAVInfo) private registry;

    // =============================
    // Events
    // =============================

    event UAVRegistered(bytes32 pid);

    event UAVBlacklisted(bytes32 pid);

    event AuthRecord(bytes32 pid, bool result, uint256 time);

    // ⭐ 新增：PID 更新事件
    event PIDUpdated(bytes32 oldPID, bytes32 newPID);

    // =============================
    // Registration
    // =============================

    function registerUAV(bytes32 pid) public {

        require(!registry[pid].registered, "Already registered");

        registry[pid] = UAVInfo(
            true,
            false,
            block.timestamp
        );

        emit UAVRegistered(pid);
    }

    // =============================
    // Validation
    // =============================

    function isValidUAV(bytes32 pid)
        public
        view
        returns (bool)
    {
        return registry[pid].registered &&
               !registry[pid].blacklisted;
    }

    // =============================
    // Blacklist
    // =============================

    function blacklistUAV(bytes32 pid) public {

        require(
            registry[pid].registered,
            "UAV not registered"
        );

        registry[pid].blacklisted = true;

        emit UAVBlacklisted(pid);
    }

    // =============================
    // Auth Record
    // =============================

    function recordAuth(
        bytes32 pid,
        bool result
    ) public {

        emit AuthRecord(
            pid,
            result,
            block.timestamp
        );
    }

    // =============================
    // ⭐ PID Rotation
    // =============================

    function updatePID(
        bytes32 oldPID,
        bytes32 newPID
    ) public {

        require(
            registry[oldPID].registered,
            "Old PID not registered"
        );

        require(
            !registry[newPID].registered,
            "New PID already exists"
        );

        UAVInfo memory info = registry[oldPID];

        // 新 PID 继承旧状态
        registry[newPID] = UAVInfo(
            true,
            info.blacklisted,
            block.timestamp
        );

        // 删除旧 PID
        delete registry[oldPID];

        emit PIDUpdated(oldPID, newPID);
    }
}
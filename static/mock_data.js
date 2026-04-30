/* global window */
// Mock dataset for offline / dummy mode. Mirrors the live API response shapes.
window.MOCK = (function () {
  var iso = function (d) { return d.toISOString(); };
  var daysAgo = function (n) { var d = new Date(); d.setDate(d.getDate() - n); return iso(d); };

  var users = [
    { id: 'u1', userName: 'a.chen', fullName: 'Alice Chen', email: 'alice.chen@acmepharma.com', status: 'Active', licenseType: 'Standard', mfaEnabled: true, roles: [], isPrivileged: false, lastLogin: daysAgo(1) },
    { id: 'u2', userName: 'b.rodriguez', fullName: 'Bruno Rodriguez', email: 'bruno.r@acmepharma.com', status: 'Active', licenseType: 'Standard', mfaEnabled: true, roles: ['SysAdmin'], isPrivileged: true, lastLogin: daysAgo(3) },
    { id: 'u3', userName: 'c.patel', fullName: 'Chitra Patel', email: 'chitra.patel@acmepharma.com', status: 'Active', licenseType: 'Standard', mfaEnabled: false, roles: [], isPrivileged: false, lastLogin: daysAgo(120) },
    { id: 'u4', userName: 'd.kim', fullName: 'David Kim', email: 'david.kim@acmepharma.com', status: 'Active', licenseType: 'Read-Only', mfaEnabled: true, roles: [], isPrivileged: false, lastLogin: daysAgo(7) },
    { id: 'u5', userName: 'e.fournier', fullName: 'Elise Fournier', email: 'elise.f@acmepharma.com', status: 'Disabled', licenseType: 'Standard', mfaEnabled: false, roles: [], isPrivileged: false, lastLogin: daysAgo(220) },
    { id: 'u6', userName: 'f.osei', fullName: 'Femi Osei', email: 'femi.osei@contractor.com', status: 'Active', licenseType: 'Standard', mfaEnabled: true, roles: ['EnvAdmin'], isPrivileged: true, lastLogin: daysAgo(14) },
    { id: 'u7', userName: 'g.tanaka', fullName: 'Gen Tanaka', email: 'gen.tanaka@acmepharma.com', status: 'Active', licenseType: 'Standard', mfaEnabled: true, roles: [], isPrivileged: false, lastLogin: daysAgo(2) },
    { id: 'u8', userName: 'h.müller', fullName: 'Hannah Müller', email: 'hannah.m@acmepharma.com', status: 'Active', licenseType: 'Standard', mfaEnabled: false, roles: [], isPrivileged: false, lastLogin: daysAgo(95) },
  ];

  var projects = [
    { id: 'p1', name: 'Phase-2 NSCLC Submission', owner: 'a.chen', ownerId: 'u1',
      collaborators: [
        { userId: 'u1', userName: 'a.chen', role: 'Owner', grantedAt: daysAgo(420), grantedBy: 'system' },
        { userId: 'u3', userName: 'c.patel', role: 'Contributor', grantedAt: daysAgo(380), grantedBy: 'a.chen' },
        { userId: 'u4', userName: 'd.kim', role: 'ResultsConsumer', grantedAt: daysAgo(200), grantedBy: 'a.chen' },
        { userId: 'u7', userName: 'g.tanaka', role: 'Admin', grantedAt: daysAgo(180), grantedBy: 'a.chen' },
      ]
    },
    { id: 'p2', name: 'Compound-127 PK Modeling', owner: 'g.tanaka', ownerId: 'u7',
      collaborators: [
        { userId: 'u7', userName: 'g.tanaka', role: 'Owner', grantedAt: daysAgo(310), grantedBy: 'system' },
        { userId: 'u1', userName: 'a.chen', role: 'Contributor', grantedAt: daysAgo(280), grantedBy: 'g.tanaka' },
        { userId: 'u8', userName: 'h.müller', role: 'Contributor', grantedAt: daysAgo(250), grantedBy: 'g.tanaka' },
      ]
    },
    { id: 'p3', name: 'Adverse Event Triage', owner: 'b.rodriguez', ownerId: 'u2',
      collaborators: [
        { userId: 'u2', userName: 'b.rodriguez', role: 'Owner', grantedAt: daysAgo(700), grantedBy: 'system' },
        { userId: 'u6', userName: 'f.osei', role: 'Admin', grantedAt: daysAgo(120), grantedBy: 'b.rodriguez' },
        { userId: 'u4', userName: 'd.kim', role: 'ResultsConsumer', grantedAt: daysAgo(60), grantedBy: 'b.rodriguez' },
      ]
    },
  ];

  var datasets = [
    { id: 'ds1', name: 'nsclc_clinical_2026', projectId: 'p1', grants: [
      { principalType: 'User', principalId: 'u1', principalName: 'a.chen', permission: 'admin' },
      { principalType: 'User', principalId: 'u3', principalName: 'c.patel', permission: 'read' },
    ]},
    { id: 'ds2', name: 'pk_compound_127_runs', projectId: 'p2', grants: [
      { principalType: 'User', principalId: 'u7', principalName: 'g.tanaka', permission: 'admin' },
      { principalType: 'User', principalId: 'u1', principalName: 'a.chen', permission: 'write' },
    ]},
  ];

  var volumes = [
    { id: 'v1', name: 'netapp-clinical-archive', volumeType: 'Nfs', mountPath: '/mnt/clinical-archive',
      readOnly: true, isPublic: false, userIds: ['u1', 'u2'], projectIds: ['p1', 'p3'], status: 'Mounted' },
    { id: 'v2', name: 'netapp-rwd-vault', volumeType: 'Nfs', mountPath: '/mnt/rwd-vault',
      readOnly: false, isPublic: false, userIds: ['u2', 'u6'], projectIds: ['p3'], status: 'Mounted' },
    { id: 'v3', name: 'gxp-validated-models', volumeType: 'Smb', mountPath: '/mnt/gxp-models',
      readOnly: true, isPublic: true, userIds: [], projectIds: ['p1', 'p2', 'p3'], status: 'Mounted' },
    { id: 'v4', name: 'efs-scratch-shared', volumeType: 'Efs', mountPath: '/mnt/scratch',
      readOnly: false, isPublic: false, userIds: ['u1','u3','u4','u7','u8'], projectIds: ['p2'], status: 'Mounted' },
  ];

  var snapshot = {
    id: 'snap_demo_20260429T120000Z',
    takenAt: new Date().toISOString(),
    takenBy: 'demo',
    scope: 'deployment',
    counts: {
      users: users.length,
      projects: projects.length,
      datasets: datasets.length,
      volumes: volumes.length,
      privilegedUsers: users.filter(function (u) { return u.isPrivileged; }).length,
    },
    users: users, projects: projects, datasets: datasets, volumes: volumes,
  };

  function userIndex() { var m = {}; users.forEach(function (u) { m[u.id] = u; }); return m; }
  function projectIndex() { var m = {}; projects.forEach(function (p) { m[p.id] = p; }); return m; }
  function daysSince(iso) { if (!iso) return null; return Math.floor((Date.now() - new Date(iso).getTime()) / 86400000); }

  function accessListing() {
    var users = userIndex();
    var rows = [];
    projects.forEach(function (p) {
      p.collaborators.forEach(function (c) {
        var u = users[c.userId] || {};
        rows.push({
          userId: c.userId, userName: c.userName || u.userName, fullName: u.fullName, email: u.email,
          status: u.status, licenseType: u.licenseType,
          projectId: p.id, projectName: p.name, role: c.role,
          grantedAt: c.grantedAt, grantedBy: c.grantedBy,
          lastLogin: u.lastLogin, daysSinceLogin: daysSince(u.lastLogin),
        });
      });
    });
    return rows;
  }

  function privileged() {
    return users.filter(function (u) { return u.isPrivileged; }).map(function (u) {
      return {
        userId: u.id, userName: u.userName, fullName: u.fullName, email: u.email,
        roles: u.roles, status: u.status, mfaEnabled: u.mfaEnabled,
        lastLogin: u.lastLogin, daysSinceLogin: daysSince(u.lastLogin),
      };
    });
  }

  function dormant(threshold) {
    threshold = threshold || 90;
    var rows = [];
    users.forEach(function (u) {
      var d = daysSince(u.lastLogin);
      var rec;
      if (u.status === 'Disabled') rec = 'Disabled — confirm offboarded';
      else if (d == null) rec = 'No login record — investigate';
      else if (d >= 180) rec = 'Disable account (>180d inactive)';
      else if (d >= threshold) rec = 'Review (>' + threshold + 'd inactive)';
      else return;
      rows.push({
        userId: u.id, userName: u.userName, fullName: u.fullName, email: u.email,
        status: u.status, lastLogin: u.lastLogin, daysSinceLogin: d, recommendation: rec,
      });
    });
    rows.sort(function (a, b) { return (b.daysSinceLogin || 9999) - (a.daysSinceLogin || 9999); });
    return rows;
  }

  function volumeAccess() {
    var users = userIndex();
    var projs = projectIndex();
    var rows = [];
    volumes.forEach(function (v) {
      if (v.isPublic) {
        rows.push({
          volumeId: v.id, volumeName: v.name, volumeType: v.volumeType, mountPath: v.mountPath, readOnly: v.readOnly,
          principalType: 'Public', principalName: 'All Users',
          permission: v.readOnly ? 'read' : 'read/write', via: 'isPublic',
        });
      }
      (v.userIds || []).forEach(function (uid) {
        var u = users[uid] || {};
        rows.push({
          volumeId: v.id, volumeName: v.name, volumeType: v.volumeType, mountPath: v.mountPath, readOnly: v.readOnly,
          principalType: 'User', principalId: uid, principalName: u.userName || uid,
          permission: v.readOnly ? 'read' : 'read/write', via: 'direct user grant',
        });
      });
      (v.projectIds || []).forEach(function (pid) {
        var p = projs[pid] || {};
        rows.push({
          volumeId: v.id, volumeName: v.name, volumeType: v.volumeType, mountPath: v.mountPath, readOnly: v.readOnly,
          principalType: 'Project', principalId: pid, principalName: p.name || pid,
          permission: v.readOnly ? 'read' : 'read/write', via: 'project mount',
        });
      });
    });
    return rows;
  }

  return {
    snapshot: snapshot,
    accessListing: accessListing,
    privileged: privileged,
    dormant: dormant,
    volumes: volumeAccess,
  };
})();

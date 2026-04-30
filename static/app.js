/* global React, ReactDOM, antd, dayjs, Highcharts, MOCK */
(function () {
  var ConfigProvider = antd.ConfigProvider;
  var Layout = antd.Layout;
  var Menu = antd.Menu;
  var Button = antd.Button;
  var Switch = antd.Switch;
  var Table = antd.Table;
  var Tag = antd.Tag;
  var Tooltip = antd.Tooltip;
  var Drawer = antd.Drawer;
  var Select = antd.Select;
  var Input = antd.Input;
  var InputNumber = antd.InputNumber;
  var message = antd.message;
  var Spin = antd.Spin;
  var Alert = antd.Alert;
  var Space = antd.Space;

  var h = React.createElement;
  var Fragment = React.Fragment;
  var useState = React.useState;
  var useEffect = React.useEffect;
  var useMemo = React.useMemo;

  var dominoTheme = {
    token: {
      colorPrimary: '#543FDE',
      colorPrimaryHover: '#3B23D1',
      colorPrimaryActive: '#311EAE',
      colorText: '#2E2E38',
      colorTextSecondary: '#65657B',
      colorTextTertiary: '#8F8FA3',
      colorSuccess: '#28A464',
      colorWarning: '#CCB718',
      colorError: '#C20A29',
      colorInfo: '#0070CC',
      colorBgContainer: '#FFFFFF',
      colorBgLayout: '#FAFAFA',
      colorBorder: '#E0E0E0',
      fontFamily: 'Inter, Lato, Helvetica Neue, Helvetica, Arial, sans-serif',
      fontSize: 14,
      borderRadius: 4,
      borderRadiusLG: 8,
    },
    components: {
      Button: { primaryShadow: 'none', defaultShadow: 'none' },
      Table: { headerBg: '#FAFAFA', rowHoverBg: '#F5F5F5' },
    },
  };

  Highcharts.setOptions({
    colors: ['#543FDE', '#0070CC', '#28A464', '#CCB718', '#FF6543', '#E835A7', '#2EDCC4', '#A9734C'],
    chart: { style: { fontFamily: 'Inter, Lato, Helvetica Neue, Arial, sans-serif' } },
  });

  // ---- API helpers ---------------------------------------------------------
  // App is served behind Domino's proxy at /<projectId>/. Strip leading '/'
  // so fetches resolve relative to the current page, not the proxy root.
  function apiUrl(path) {
    return path.charAt(0) === '/' ? path.slice(1) : path;
  }
  function apiGet(path) {
    return fetch(apiUrl(path)).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }
  function apiPost(path) {
    return fetch(apiUrl(path), { method: 'POST' }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }

  // ---- Reusable ------------------------------------------------------------
  function StatCard(props) {
    var cls = 'stat-card' + (props.onClick ? ' stat-card-clickable' : '') + (props.active ? ' stat-card-active' : '');
    return h('div', { className: cls, onClick: props.onClick || null },
      h('div', { className: 'stat-card-label' }, props.label),
      h('div', { className: 'stat-card-value ' + (props.color || '') }, props.value),
      props.sub ? h('div', { className: 'stat-card-sub' }, props.sub) : null
    );
  }

  function SnapshotBanner(props) {
    if (!props.snapshot) return null;
    var taken = props.snapshot.takenAt ? dayjs(props.snapshot.takenAt).format('YYYY-MM-DD HH:mm UTC') : '—';
    var label = props.live ? 'Live view' : 'Snapshot ' + (props.snapshot.id || '—');
    return h('span', { className: 'snapshot-banner' }, label, ' · ', taken);
  }

  function fmtDate(iso) {
    if (!iso) return h('span', { className: 'text-muted' }, '—');
    return dayjs(iso).format('YYYY-MM-DD');
  }

  function roleTag(role) {
    if (!role) return null;
    return h(Tag, { className: 'role-tag-' + role, bordered: true }, role);
  }

  function statusTag(status) {
    if (status === 'Disabled') return h(Tag, { color: 'red' }, 'Disabled');
    if (status === 'Active') return h(Tag, { color: 'green' }, 'Active');
    return h(Tag, null, status || '—');
  }

  function volumeTypeTag(t) {
    var color = t === 'Nfs' ? 'purple' : t === 'Smb' ? 'blue' : t === 'Efs' ? 'cyan' : 'default';
    var label = t === 'Nfs' ? 'NetApp / NFS' : (t || 'Generic');
    return h(Tag, { color: color }, label);
  }

  // ---- Pages ---------------------------------------------------------------

  function Dashboard(props) {
    var snap = props.snap;
    var counts = (snap && snap.counts) || {};

    return h('div', null,
      h('div', { className: 'stats-row' },
        h(StatCard, { label: 'Users', value: counts.users || 0, color: 'primary',
          onClick: function () { props.onNav('users'); } }),
        h(StatCard, { label: 'Privileged users', value: counts.privilegedUsers || 0, color: 'danger',
          sub: 'SysAdmin / EnvAdmin / Org Owner', onClick: function () { props.onNav('privileged'); } }),
        h(StatCard, { label: 'Projects', value: counts.projects || 0, color: 'info' }),
        h(StatCard, { label: 'Datasets', value: counts.datasets || 0 }),
        h(StatCard, { label: 'External volumes', value: counts.volumes || 0, color: 'success',
          sub: 'NetApp / NFS / SMB / EFS', onClick: function () { props.onNav('volumes'); } })
      ),
      h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, 'Periodic access review'),
            h('div', { className: 'panel-sub' }, 'GxP customers (Annex 11 §12 / GAMP 5 O8) typically review user access quarterly. Take a snapshot, sign it, archive the PDF.')
          ),
          h(Button, { type: 'primary', onClick: props.onTakeSnapshot, loading: props.takingSnapshot },
            'Take snapshot now')
        ),
        h('p', { style: { color: '#65657B', fontSize: 13, marginTop: 0, marginBottom: 0 } },
          'Each snapshot captures who has access to which projects, datasets, and external data volumes (NetApp / NFS / SMB / EFS) at this exact moment. Snapshots are immutable and exportable to PDF/CSV for auditor delivery.')
      )
    );
  }

  function AccessListingPage(props) {
    var rows = props.rows || [];
    var _f = useState({ search: '', role: null, status: null });
    var f = _f[0]; var setF = _f[1];

    var roles = useMemo(function () {
      var s = {}; rows.forEach(function (r) { if (r.role) s[r.role] = true; });
      return Object.keys(s).sort();
    }, [rows]);

    var filtered = useMemo(function () {
      var q = (f.search || '').toLowerCase();
      return rows.filter(function (r) {
        if (f.role && r.role !== f.role) return false;
        if (f.status && r.status !== f.status) return false;
        if (q) {
          var hay = ((r.userName || '') + ' ' + (r.email || '') + ' ' + (r.projectName || '') + ' ' + (r.fullName || '')).toLowerCase();
          if (hay.indexOf(q) === -1) return false;
        }
        return true;
      });
    }, [rows, f]);

    var columns = [
      { title: 'User', dataIndex: 'userName', key: 'userName', width: 160, fixed: 'left',
        sorter: function (a, b) { return (a.userName || '').localeCompare(b.userName || ''); },
        render: function (v, r) {
          return h('div', null,
            h('div', { style: { fontWeight: 500 } }, v || '—'),
            r.fullName ? h('div', { style: { fontSize: 11, color: '#8F8FA3' } }, r.fullName) : null
          );
        }
      },
      { title: 'Email', dataIndex: 'email', key: 'email', width: 220, ellipsis: true,
        render: function (v) { return v ? h(Tooltip, { title: v }, v) : h('span', { className: 'text-muted' }, '—'); } },
      { title: 'Project', dataIndex: 'projectName', key: 'projectName', width: 220, ellipsis: true,
        sorter: function (a, b) { return (a.projectName || '').localeCompare(b.projectName || ''); } },
      { title: 'Role', dataIndex: 'role', key: 'role', width: 140,
        filters: roles.map(function (r) { return { text: r, value: r }; }),
        onFilter: function (value, record) { return record.role === value; },
        render: function (v) { return roleTag(v); } },
      { title: 'Status', dataIndex: 'status', key: 'status', width: 100,
        render: function (v) { return statusTag(v); } },
      { title: 'License', dataIndex: 'licenseType', key: 'licenseType', width: 110 },
      { title: 'Last login', dataIndex: 'lastLogin', key: 'lastLogin', width: 130,
        sorter: function (a, b) { return new Date(a.lastLogin || 0) - new Date(b.lastLogin || 0); },
        render: function (v, r) {
          if (!v) return h('span', { className: 'text-muted' }, 'never');
          var d = r.daysSinceLogin;
          var color = d > 180 ? '#C20A29' : d > 90 ? '#B58900' : '#65657B';
          return h(Tooltip, { title: dayjs(v).format('YYYY-MM-DD HH:mm') },
            h('span', { style: { color: color } }, d + 'd ago'));
        }
      },
      { title: 'Granted', dataIndex: 'grantedAt', key: 'grantedAt', width: 110,
        render: function (v) { return fmtDate(v); } },
    ];

    return h('div', null,
      h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, 'User access listing'),
            h('div', { className: 'panel-sub' }, filtered.length + ' of ' + rows.length + ' rows · User × Project × Role')
          ),
          h(Space, null,
            h(Input.Search, { placeholder: 'Search user, email, project',
              allowClear: true, style: { width: 280 },
              onSearch: function (v) { setF(Object.assign({}, f, { search: v })); },
              onChange: function (e) { setF(Object.assign({}, f, { search: e.target.value })); } }),
            h(Select, { placeholder: 'Role', allowClear: true, style: { width: 150 },
              value: f.role, onChange: function (v) { setF(Object.assign({}, f, { role: v })); },
              options: roles.map(function (r) { return { label: r, value: r }; }) }),
            h(Select, { placeholder: 'Status', allowClear: true, style: { width: 130 },
              value: f.status, onChange: function (v) { setF(Object.assign({}, f, { status: v })); },
              options: [{ label: 'Active', value: 'Active' }, { label: 'Disabled', value: 'Disabled' }] }),
            h(Button, { onClick: function () { props.onExport('access-listing', 'csv'); } }, 'Export CSV'),
            h(Button, { onClick: function () { props.onExport('access-listing', 'pdf'); } }, 'Export PDF')
          )
        ),
        h(Table, {
          dataSource: filtered, columns: columns, rowKey: function (r) { return r.userId + '|' + r.projectId; },
          size: 'small', pagination: { pageSize: 25, showSizeChanger: true },
          scroll: { x: 1100 }
        })
      )
    );
  }

  function PrivilegedPage(props) {
    var rows = props.rows || [];
    var columns = [
      { title: 'User', dataIndex: 'userName', key: 'userName', width: 160,
        render: function (v, r) {
          return h('div', null,
            h('div', { style: { fontWeight: 500 } }, v || '—'),
            r.fullName ? h('div', { style: { fontSize: 11, color: '#8F8FA3' } }, r.fullName) : null
          );
        }
      },
      { title: 'Email', dataIndex: 'email', key: 'email', width: 220, ellipsis: true },
      { title: 'Privileged roles', dataIndex: 'roles', key: 'roles', width: 260,
        render: function (rs) {
          if (!rs || !rs.length) return h('span', { className: 'text-muted' }, '—');
          return rs.map(function (r) { return h(Tag, { key: r, color: 'red' }, r); });
        }
      },
      { title: 'Status', dataIndex: 'status', key: 'status', width: 100, render: statusTag },
      { title: 'MFA', dataIndex: 'mfaEnabled', key: 'mfa', width: 80,
        render: function (v) { return v
          ? h(Tag, { color: 'green' }, '✓ On')
          : h(Tooltip, { title: 'MFA not enabled — auditor flag for privileged users' },
              h(Tag, { color: 'red' }, '⚠ Off')); }
      },
      { title: 'Last login', dataIndex: 'lastLogin', key: 'lastLogin', width: 140,
        render: function (v, r) {
          if (!v) return h('span', { className: 'text-muted' }, 'never');
          return h(Tooltip, { title: dayjs(v).format('YYYY-MM-DD HH:mm') }, r.daysSinceLogin + 'd ago');
        }
      },
    ];

    return h('div', { className: 'panel' },
      h('div', { className: 'panel-header' },
        h('div', null,
          h('div', { className: 'panel-title' }, 'Privileged user report'),
          h('div', { className: 'panel-sub' }, rows.length + ' privileged users · review quarterly per GAMP 5 O8')
        ),
        h(Space, null,
          h(Button, { onClick: function () { props.onExport('privileged', 'csv'); } }, 'Export CSV'),
          h(Button, { onClick: function () { props.onExport('privileged', 'pdf'); } }, 'Export PDF')
        )
      ),
      rows.length === 0
        ? h('div', { className: 'empty-state' },
            h('div', { className: 'empty-state-title' }, 'No privileged users found'),
            h('div', { className: 'empty-state-body' }, 'Either nobody holds an admin role, or the service account lacks visibility. Confirm the API_KEY_OVERRIDE has admin scope.'))
        : h(Table, { dataSource: rows, columns: columns, rowKey: 'userId', size: 'small',
            pagination: { pageSize: 25 } })
    );
  }

  function VolumesPage(props) {
    var rows = props.rows || [];
    var _f = useState({ type: null, search: '' });
    var f = _f[0]; var setF = _f[1];

    var filtered = useMemo(function () {
      var q = (f.search || '').toLowerCase();
      return rows.filter(function (r) {
        if (f.type && r.volumeType !== f.type) return false;
        if (q) {
          var hay = ((r.volumeName || '') + ' ' + (r.principalName || '') + ' ' + (r.mountPath || '')).toLowerCase();
          if (hay.indexOf(q) === -1) return false;
        }
        return true;
      });
    }, [rows, f]);

    var stats = useMemo(function () {
      var byType = {};
      var pubCount = 0;
      var rwCount = 0;
      rows.forEach(function (r) {
        byType[r.volumeType] = (byType[r.volumeType] || 0) + 1;
        if (r.principalType === 'Public') pubCount += 1;
        if (r.permission === 'read/write') rwCount += 1;
      });
      return { byType: byType, pubCount: pubCount, rwCount: rwCount };
    }, [rows]);

    var columns = [
      { title: 'Volume', dataIndex: 'volumeName', key: 'volumeName', width: 200,
        sorter: function (a, b) { return (a.volumeName || '').localeCompare(b.volumeName || ''); },
        render: function (v, r) {
          return h('div', null,
            h('div', { style: { fontWeight: 500 } }, v),
            h('div', { style: { fontSize: 11, color: '#8F8FA3' } }, r.mountPath));
        } },
      { title: 'Type', dataIndex: 'volumeType', key: 'volumeType', width: 130,
        filters: [{text:'NetApp / NFS', value:'Nfs'}, {text:'SMB', value:'Smb'}, {text:'EFS', value:'Efs'}, {text:'Generic', value:'Generic'}],
        onFilter: function (v, r) { return r.volumeType === v; },
        render: volumeTypeTag },
      { title: 'Principal', dataIndex: 'principalType', key: 'pType', width: 110,
        render: function (v) {
          var color = v === 'Public' ? 'red' : v === 'User' ? 'blue' : 'purple';
          return h(Tag, { color: color }, v);
        } },
      { title: 'Name', dataIndex: 'principalName', key: 'pName', width: 220, ellipsis: true },
      { title: 'Permission', dataIndex: 'permission', key: 'perm', width: 120,
        render: function (v) {
          return v === 'read/write'
            ? h(Tag, { color: 'orange' }, 'read/write')
            : h(Tag, null, 'read');
        } },
      { title: 'Granted via', dataIndex: 'via', key: 'via', width: 180,
        render: function (v) { return h('span', { style: { fontSize: 12, color: '#65657B' } }, v); } },
    ];

    return h('div', null,
      h('div', { className: 'stats-row' },
        h(StatCard, { label: 'NetApp / NFS rows', value: stats.byType.Nfs || 0, color: 'primary' }),
        h(StatCard, { label: 'SMB rows', value: stats.byType.Smb || 0, color: 'info' }),
        h(StatCard, { label: 'EFS rows', value: stats.byType.Efs || 0 }),
        h(StatCard, { label: 'Public-mounted', value: stats.pubCount, color: 'danger', sub: 'isPublic = true' }),
        h(StatCard, { label: 'Read/write grants', value: stats.rwCount, color: 'warning' })
      ),
      h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, 'External data volume access'),
            h('div', { className: 'panel-sub' }, filtered.length + ' of ' + rows.length + ' grants · NetApp / NFS / SMB / EFS via /v4/datamount')
          ),
          h(Space, null,
            h(Input.Search, { placeholder: 'Search volume, mount, principal',
              allowClear: true, style: { width: 280 },
              onChange: function (e) { setF(Object.assign({}, f, { search: e.target.value })); } }),
            h(Select, { placeholder: 'Volume type', allowClear: true, style: { width: 150 },
              value: f.type, onChange: function (v) { setF(Object.assign({}, f, { type: v })); },
              options: [
                { label: 'NetApp / NFS', value: 'Nfs' },
                { label: 'SMB', value: 'Smb' },
                { label: 'EFS', value: 'Efs' },
                { label: 'Generic', value: 'Generic' },
              ] }),
            h(Button, { onClick: function () { props.onExport('volumes', 'csv'); } }, 'Export CSV'),
            h(Button, { onClick: function () { props.onExport('volumes', 'pdf'); } }, 'Export PDF')
          )
        ),
        h(Table, {
          dataSource: filtered, columns: columns, size: 'small',
          rowKey: function (r) { return r.volumeId + '|' + r.principalType + '|' + (r.principalId || 'public'); },
          pagination: { pageSize: 25 }
        })
      )
    );
  }

  function VerifyUserPage(props) {
    var _u = useState(''); var userName = _u[0]; var setUserName = _u[1];
    var _data = useState(null); var data = _data[0]; var setData = _data[1];
    var _loading = useState(false); var loading = _loading[0]; var setLoading = _loading[1];
    var _gt = useState({ expectedProjects: '', expectedRoles: '', expectedVolumes: '' });
    var gt = _gt[0]; var setGt = _gt[1];
    var _rec = useState(null); var rec = _rec[0]; var setRec = _rec[1];

    function lookup() {
      if (!userName.trim()) return;
      setLoading(true); setRec(null);
      apiGet('/api/verify/user/' + encodeURIComponent(userName.trim()))
        .then(setData).catch(function (e) { message.error(e.message); setData(null); })
        .finally(function () { setLoading(false); });
    }

    function runReconcile() {
      var payload = { userName: userName.trim() };
      try {
        if (gt.expectedProjects.trim()) {
          payload.expectedProjects = gt.expectedProjects.trim().split('\n').map(function (l) {
            var parts = l.split('|').map(function (s) { return s.trim(); });
            return { projectName: parts[0], role: parts[1] || null };
          }).filter(function (e) { return e.projectName; });
        }
        if (gt.expectedRoles.trim()) {
          payload.expectedRoles = gt.expectedRoles.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
        }
        if (gt.expectedVolumes.trim()) {
          payload.expectedVolumes = gt.expectedVolumes.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
        }
      } catch (e) { message.error('Could not parse ground truth: ' + e.message); return; }
      fetch(apiUrl('/api/verify/reconcile'), {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }).then(function (r) { return r.json(); }).then(setRec)
        .catch(function (e) { message.error(e.message); });
    }

    var projectCols = [
      { title: 'Project', dataIndex: 'projectName', key: 'p', ellipsis: true },
      { title: 'Role at this moment', dataIndex: 'role', key: 'r', width: 180,
        render: function (v) { return roleTag(v); } },
      { title: 'Granted', dataIndex: 'grantedAt', key: 'g', width: 130, render: fmtDate },
    ];
    var dsCols = [
      { title: 'Dataset', dataIndex: 'datasetName', key: 'd', ellipsis: true },
      { title: 'Permission', dataIndex: 'permission', key: 'p', width: 140,
        render: function (v) { return v ? h(Tag, { color: v === 'Owner' ? 'red' : v === 'Editor' ? 'orange' : 'blue' }, v) : '—'; } },
      { title: 'Source', dataIndex: 'source', key: 's', width: 180, render: function (v) { return h('span', { style: { fontSize: 11, color: '#65657B' } }, v || '—'); } },
    ];
    var volCols = [
      { title: 'Volume', dataIndex: 'volumeName', key: 'v', ellipsis: true },
      { title: 'Type', dataIndex: 'volumeType', key: 't', width: 130, render: volumeTypeTag },
      { title: 'Permission', dataIndex: 'permission', key: 'p', width: 140,
        render: function (v) { return v ? h(Tag, { color: v === 'Owner' ? 'red' : v === 'Editor' ? 'orange' : 'blue' }, v) : '—'; } },
    ];

    return h('div', null,
      h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, 'Verify a user'),
            h('div', { className: 'panel-sub' }, 'Spot-check what one user can access at this exact moment — projects + role, datasets, NetApp volumes')
          )
        ),
        h(Space, null,
          h(Input, { placeholder: 'username (e.g. matt_tendler_domino)', value: userName,
            onChange: function (e) { setUserName(e.target.value); }, onPressEnter: lookup, style: { width: 360 } }),
          h(Button, { type: 'primary', onClick: lookup, loading: loading }, 'Look up user')
        )
      ),
      data ? h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, data.user.fullName + ' (' + data.user.userName + ')'),
            h('div', { className: 'panel-sub' }, data.user.email + ' · ' + (data.user.licenseType || '—') + ' · ' + (data.user.status || '—'))
          ),
          h(Space, null,
            data.isPrivileged ? h(Tag, { color: 'red' }, 'Privileged') : null,
            (data.globalRoles || []).map(function (r) { return h(Tag, { key: r, color: 'purple' }, r); })
          )
        ),
        h('div', { className: 'stats-row' },
          h(StatCard, { label: 'Projects', value: data.summary.projectCount, color: 'primary' }),
          h(StatCard, { label: 'Datasets', value: data.summary.datasetCount, color: 'info' }),
          h(StatCard, { label: 'Volumes', value: data.summary.volumeCount, color: 'success' })
        ),
        h('div', { className: 'panel-title', style: { marginTop: 8 } }, 'Project memberships'),
        h(Table, { dataSource: data.projectMemberships, columns: projectCols, size: 'small', rowKey: 'projectId', pagination: false }),
        h('div', { className: 'panel-title', style: { marginTop: 16 } }, 'Dataset grants'),
        h(Table, { dataSource: data.datasetGrants, columns: dsCols, size: 'small', rowKey: 'datasetId', pagination: false }),
        h('div', { className: 'panel-title', style: { marginTop: 16 } }, 'NetApp volume access'),
        h(Table, { dataSource: data.volumeAccess, columns: volCols, size: 'small', rowKey: 'volumeId', pagination: false })
      ) : null,
      data ? h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, 'Reconcile against ground truth'),
            h('div', { className: 'panel-sub' }, 'Paste your expected access — we mark each row pass/fail')
          )
        ),
        h(Space, { direction: 'vertical', style: { width: '100%' } },
          h('div', null,
            h('div', { style: { fontSize: 12, color: '#65657B', marginBottom: 4 } }, 'Expected projects (one per line: "name | role")'),
            h(Input.TextArea, { rows: 4, value: gt.expectedProjects,
              placeholder: 'supply_risk_radar | Owner\nbiomarker_forge | Owner',
              onChange: function (e) { setGt(Object.assign({}, gt, { expectedProjects: e.target.value })); } })
          ),
          h('div', null,
            h('div', { style: { fontSize: 12, color: '#65657B', marginBottom: 4 } }, 'Expected global roles (comma-separated)'),
            h(Input, { value: gt.expectedRoles, placeholder: 'SysAdmin, Practitioner',
              onChange: function (e) { setGt(Object.assign({}, gt, { expectedRoles: e.target.value })); } })
          ),
          h('div', null,
            h('div', { style: { fontSize: 12, color: '#65657B', marginBottom: 4 } }, 'Expected NetApp volumes (comma-separated)'),
            h(Input, { value: gt.expectedVolumes, placeholder: 'NetApp_App, skill-test-volume',
              onChange: function (e) { setGt(Object.assign({}, gt, { expectedVolumes: e.target.value })); } })
          ),
          h(Button, { type: 'primary', onClick: runReconcile }, 'Run reconciliation')
        ),
        rec ? h('div', { style: { marginTop: 16 } },
          h(Alert, {
            type: rec.summary.allPass ? 'success' : 'warning',
            showIcon: true,
            message: rec.summary.allPass
              ? 'All expectations matched'
              : 'Reconciliation summary — see details below',
            description: 'Projects: ' + rec.summary.projectsPass + '/' + rec.summary.projectsTotal +
              ' · Roles: ' + rec.summary.rolesPass + '/' + rec.summary.rolesTotal +
              ' · Volumes: ' + rec.summary.volumesPass + '/' + rec.summary.volumesTotal,
            style: { marginBottom: 12 },
          }),
          rec.findings.projects.length ? h(Table, {
            title: function () { return 'Project findings'; },
            dataSource: rec.findings.projects, size: 'small', pagination: false,
            rowKey: 'projectName', columns: [
              { title: 'Project', dataIndex: 'projectName' },
              { title: 'Expected', dataIndex: 'expectedRole', width: 140 },
              { title: 'Actual', dataIndex: 'actualRole', width: 140 },
              { title: 'Pass', dataIndex: 'pass', width: 80,
                render: function (v) { return v ? h(Tag, { color: 'green' }, '✓') : h(Tag, { color: 'red' }, '✗'); } },
            ]}) : null,
          rec.findings.roles.length ? h(Table, {
            title: function () { return 'Global role findings'; },
            dataSource: rec.findings.roles, size: 'small', pagination: false,
            rowKey: 'role', columns: [
              { title: 'Role', dataIndex: 'role' },
              { title: 'Pass', dataIndex: 'pass', width: 80,
                render: function (v) { return v ? h(Tag, { color: 'green' }, '✓') : h(Tag, { color: 'red' }, '✗'); } },
            ]}) : null,
          rec.findings.volumes.length ? h(Table, {
            title: function () { return 'Volume findings'; },
            dataSource: rec.findings.volumes, size: 'small', pagination: false,
            rowKey: 'volumeName', columns: [
              { title: 'Volume', dataIndex: 'volumeName' },
              { title: 'Pass', dataIndex: 'pass', width: 80,
                render: function (v) { return v ? h(Tag, { color: 'green' }, '✓') : h(Tag, { color: 'red' }, '✗'); } },
            ]}) : null
        ) : null
      ) : null
    );
  }

  function DebugPage(props) {
    var _d = useState(null); var data = _d[0]; var setData = _d[1];
    var _l = useState(false); var loading = _l[0]; var setLoading = _l[1];

    function refresh() {
      setLoading(true);
      apiGet('/api/debug').then(setData).catch(function (e) { message.error(e.message); })
        .finally(function () { setLoading(false); });
    }
    useEffect(function () { refresh(); }, []);

    if (loading || !data) return h(Spin, { style: { display: 'block', margin: '60px auto' } });

    var ep = data.endpoints || {};
    function epCard(key, ok, body) {
      return h('div', { key: key, className: 'panel', style: { marginBottom: 12 } },
        h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } },
          h('div', null,
            h('strong', null, key),
            h('div', { style: { fontSize: 11, color: '#8F8FA3' } }, body.path || '')
          ),
          ok ? h(Tag, { color: 'green' }, '✓ OK') : h(Tag, { color: 'orange' }, '⚠ partial')
        ),
        body.note ? h('div', { style: { fontSize: 11, color: '#65657B', marginTop: 4 } }, body.note) : null,
        body.count != null ? h('div', { style: { fontSize: 11, color: '#65657B', marginTop: 2 } }, 'rows returned: ' + body.count) : null,
        body.sampleCount != null ? h('div', { style: { fontSize: 11, color: '#65657B', marginTop: 2 } }, 'sample fetched: ' + body.sampleCount + ' events') : null
      );
    }

    var top = data.lastSnapshot && data.lastSnapshot.projectionSummary || {};
    var counts = (top.eventCounts) || {};
    var sortedCounts = Object.keys(counts).map(function (k) { return [k, counts[k]]; })
      .sort(function (a, b) { return b[1] - a[1]; });

    return h('div', null,
      h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, 'Identity & connectivity'),
            h('div', { className: 'panel-sub' }, data.host)
          ),
          h(Button, { onClick: refresh, size: 'small' }, 'Refresh')
        ),
        h('div', null,
          h('div', null, h('strong', null, 'Calling principal: '),
            data.principal && data.principal.name,
            data.principal && data.principal.isAdmin ? h(Tag, { color: 'red', style: { marginLeft: 8 } }, 'isAdmin: true') : null),
          h('div', { style: { fontSize: 12, color: '#65657B', marginTop: 4 } },
            'Self-roles (from /v4/users/self): ',
            (data.principal && data.principal.selfRoles && data.principal.selfRoles.length)
              ? data.principal.selfRoles.join(', ')
              : '(none — limited to org-Admin and audit-projected roles)')
        )
      ),
      h('div', { className: 'panel' },
        h('div', { className: 'panel-title' }, 'Endpoint coverage'),
        epCard('users', ep.users && ep.users.ok, ep.users || {}),
        epCard('projects', ep.projects && ep.projects.ok, ep.projects || {}),
        epCard('datamount', ep.datamount && ep.datamount.count > 0, ep.datamount || {}),
        epCard('audit', ep.audit && ep.audit.ok, ep.audit || {}),
        epCard('datasetGrants', true, ep.datasetGrants || {})
      ),
      data.lastSnapshot ? h('div', { className: 'panel' },
        h('div', { className: 'panel-title' }, 'Last snapshot · ' + data.lastSnapshot.id),
        h('div', { className: 'panel-sub' }, dayjs(data.lastSnapshot.takenAt).format('YYYY-MM-DD HH:mm UTC')),
        h('div', { className: 'stats-row', style: { marginTop: 12 } },
          h(StatCard, { label: 'Users', value: data.lastSnapshot.counts.users }),
          h(StatCard, { label: 'Projects', value: data.lastSnapshot.counts.projects }),
          h(StatCard, { label: 'Datasets', value: data.lastSnapshot.counts.datasets }),
          h(StatCard, { label: 'Volumes', value: data.lastSnapshot.counts.volumes }),
          h(StatCard, { label: 'Audit events replayed', value: top.totalEvents || 0, color: 'primary' }),
          h(StatCard, { label: 'Volumes via audit only', value: top.discoveredVolumeCount || 0, color: 'warning' })
        )
      ) : null,
      h('div', { className: 'panel' },
        h('div', { className: 'panel-title' }, 'Audit event types replayed (top 30)'),
        h(Table, {
          size: 'small', pagination: false,
          dataSource: sortedCounts.slice(0, 30).map(function (e) { return { name: e[0], count: e[1] }; }),
          rowKey: 'name',
          columns: [
            { title: 'Event', dataIndex: 'name' },
            { title: 'Count', dataIndex: 'count', width: 100, align: 'right' },
          ],
        })
      )
    );
  }

  function SnapshotsPage(props) {
    var snaps = props.snaps || [];
    var columns = [
      { title: 'Snapshot ID', dataIndex: 'id', key: 'id', width: 280,
        render: function (v) { return h('code', { style: { fontSize: 12 } }, v); } },
      { title: 'Taken', dataIndex: 'takenAt', key: 'takenAt', width: 200,
        render: function (v) { return v ? dayjs(v).format('YYYY-MM-DD HH:mm UTC') : '—'; } },
      { title: 'By', dataIndex: 'takenBy', key: 'by', width: 140 },
      { title: 'Users', dataIndex: ['counts', 'users'], key: 'u', align: 'right', width: 90 },
      { title: 'Projects', dataIndex: ['counts', 'projects'], key: 'p', align: 'right', width: 90 },
      { title: 'Datasets', dataIndex: ['counts', 'datasets'], key: 'd', align: 'right', width: 90 },
      { title: 'Volumes', dataIndex: ['counts', 'volumes'], key: 'v', align: 'right', width: 90 },
      { title: 'Privileged', dataIndex: ['counts', 'privilegedUsers'], key: 'pr', align: 'right', width: 100 },
      { title: 'Signed', dataIndex: 'signed', key: 'signed', width: 90,
        render: function (v) { return v ? h(Tag, { color: 'green' }, '✓ Signed') : h(Tag, null, 'Unsigned'); } },
    ];
    return h('div', { className: 'panel' },
      h('div', { className: 'panel-header' },
        h('div', null,
          h('div', { className: 'panel-title' }, 'Snapshots library'),
          h('div', { className: 'panel-sub' }, snaps.length + ' archived snapshots · stored at /domino/datasets/local/permissions_app/snapshots/')
        ),
        h(Button, { type: 'primary', onClick: props.onTakeSnapshot, loading: props.takingSnapshot },
          'Take snapshot now')
      ),
      snaps.length === 0
        ? h('div', { className: 'empty-state' },
            h('div', { className: 'empty-state-title' }, 'No snapshots yet'),
            h('div', { className: 'empty-state-body' }, 'Take your first snapshot to begin building an audit trail.'))
        : h(Table, { dataSource: snaps, columns: columns, rowKey: 'id', size: 'small',
            pagination: { pageSize: 25 } })
    );
  }

  // ---- App shell -----------------------------------------------------------

  function App() {
    var _conn = useState(false); var connected = _conn[0]; var setConnected = _conn[1];
    var _hi = useState(null); var healthInfo = _hi[0]; var setHealthInfo = _hi[1];
    var _useDummy = useState(true); var useDummy = _useDummy[0]; var setUseDummy = _useDummy[1];
    var _page = useState('dashboard'); var page = _page[0]; var setPage = _page[1];
    var _loading = useState(false); var loading = _loading[0]; var setLoading = _loading[1];
    var _taking = useState(false); var taking = _taking[0]; var setTaking = _taking[1];

    var _snap = useState(null); var snap = _snap[0]; var setSnap = _snap[1];
    var _access = useState([]); var access = _access[0]; var setAccess = _access[1];
    var _priv = useState([]); var priv = _priv[0]; var setPriv = _priv[1];
    var _vols = useState([]); var vols = _vols[0]; var setVols = _vols[1];
    var _snaps = useState([]); var snaps = _snaps[0]; var setSnaps = _snaps[1];

    function loadDummy() {
      setSnap(window.MOCK.snapshot);
      setAccess(window.MOCK.accessListing());
      setPriv(window.MOCK.privileged());
      setVols(window.MOCK.volumes());
      setSnaps([{ id: window.MOCK.snapshot.id, takenAt: window.MOCK.snapshot.takenAt, takenBy: 'demo',
        counts: window.MOCK.snapshot.counts, signed: false }]);
    }

    function loadLive() {
      setLoading(true);
      Promise.all([
        apiGet('/api/reports/access-listing'),
        apiGet('/api/reports/privileged'),
        apiGet('/api/reports/volumes'),
        apiGet('/api/snapshots'),
      ]).then(function (results) {
        setSnap(results[0].snapshot);
        setAccess(results[0].rows || []);
        setPriv(results[1].rows || []);
        setVols(results[2].rows || []);
        setSnaps(results[3] || []);
      }).catch(function (e) {
        console.error('live load failed', e);
        message.error('Live data unavailable — switching to dummy data');
        setUseDummy(true);
        loadDummy();
      }).finally(function () { setLoading(false); });
    }

    // On mount: probe health, decide live vs dummy.
    useEffect(function () {
      apiGet('/api/health').then(function (hr) {
        setHealthInfo(hr || null);
        if (hr && hr.ok) {
          setConnected(true); setUseDummy(false); loadLive();
        } else {
          setConnected(false); setUseDummy(true); loadDummy();
        }
      }).catch(function () {
        setConnected(false); setUseDummy(true); loadDummy();
      });
    }, []);

    // Re-load when toggle flipped
    useEffect(function () {
      if (useDummy) loadDummy(); else if (connected) loadLive();
    }, [useDummy]);

    function takeSnapshot() {
      if (useDummy) { message.info('Dummy mode: snapshot not persisted'); return; }
      setTaking(true);
      apiPost('/api/snapshots').then(function () {
        message.success('Snapshot captured');
        loadLive();
      }).catch(function (e) {
        console.error(e); message.error('Snapshot failed: ' + e.message);
      }).finally(function () { setTaking(false); });
    }

    function exportReport(key, format) {
      if (useDummy) { message.info('Switch to live data to export'); return; }
      var url = apiUrl('/api/exports/' + key + '.' + format);
      window.open(url, '_blank');
    }

    var menuItems = [
      { key: 'dashboard', label: 'Dashboard' },
      { key: 'users', label: 'User access listing' },
      { key: 'verify', label: 'Verify a user' },
      { key: 'privileged', label: 'Privileged users' },
      { key: 'volumes', label: 'External volumes' },
      { key: 'snapshots', label: 'Snapshots' },
      { key: 'debug', label: 'Debug' },
    ];

    var pageEl;
    if (page === 'dashboard') {
      pageEl = h(Dashboard, { snap: snap,
        onNav: setPage, onTakeSnapshot: takeSnapshot, takingSnapshot: taking });
    } else if (page === 'users') {
      pageEl = h(AccessListingPage, { rows: access, onExport: exportReport });
    } else if (page === 'privileged') {
      pageEl = h(PrivilegedPage, { rows: priv, onExport: exportReport });
    } else if (page === 'volumes') {
      pageEl = h(VolumesPage, { rows: vols, onExport: exportReport });
    } else if (page === 'snapshots') {
      pageEl = h(SnapshotsPage, { snaps: snaps, onTakeSnapshot: takeSnapshot, takingSnapshot: taking });
    } else if (page === 'verify') {
      pageEl = h(VerifyUserPage, {});
    } else if (page === 'debug') {
      pageEl = h(DebugPage, {});
    }

    return h(ConfigProvider, { theme: dominoTheme },
      h('div', { className: 'app-layout-no-topnav' },
        h('div', { className: 'app-sider' },
          h('div', { className: 'brand' },
            h('div', { className: 'brand-title' }, 'Access Review'),
            h('div', { className: 'brand-sub' }, 'Domino · GxP-ready')
          ),
          h(Menu, { mode: 'inline', selectedKeys: [page],
            items: menuItems, onClick: function (e) { setPage(e.key); },
            style: { borderRight: 0 } })
        ),
        h('div', { className: 'main-content' },
          h('div', { className: 'search-card' },
            h('div', { className: 'search-card-identity' },
              h('span', { className: 'app-title' }, 'Domino Access Review'),
              h('span', { className: 'app-subtitle' }, 'Who has access to what — projects, datasets, and external volumes')
            ),
            h('div', { className: 'search-card-controls' },
              h(SnapshotBanner, { snapshot: snap, live: !useDummy && connected }),
              h('div', { className: 'dummy-data-toggle' },
                h(Tooltip, { title: connected ? 'Live data is available — toggle on to demo with mock data' : 'Live API unavailable — using dummy data' },
                  h('span', null, 'Dummy data')),
                h(Switch, { checked: useDummy, onChange: setUseDummy, size: 'small' })
              ),
              h(Button, { type: 'primary', onClick: takeSnapshot, loading: taking,
                disabled: useDummy }, 'Take snapshot')
            )
          ),
          (healthInfo && healthInfo.endpoints && !useDummy)
            ? (function () {
                var ep = healthInfo.endpoints;
                var gaps = [];
                if (!ep.datamount) gaps.push('External Data Volumes — /remotefs/v1/volumes returned empty (caller may lack cross-user volume visibility)');
                if (!ep.auditevents) gaps.push('Audit events — /api/audittrail/v1/search returned empty');
                if (!gaps.length) return null;
                return h(Alert, {
                  type: 'warning', showIcon: true, style: { marginBottom: 16 },
                  message: 'Known data gaps for this Domino instance',
                  description: h('ul', { style: { margin: '6px 0 0 16px', paddingLeft: 0 } },
                    gaps.map(function (g, i) { return h('li', { key: i, style: { fontSize: 12 } }, g); }))
                });
              })()
            : null,
          loading
            ? h('div', { style: { textAlign: 'center', padding: 60 } }, h(Spin, { size: 'large' }))
            : pageEl
        )
      )
    );
  }

  ReactDOM.createRoot(document.getElementById('root')).render(h(App));
})();

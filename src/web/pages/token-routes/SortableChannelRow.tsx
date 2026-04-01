import { useState, type CSSProperties } from 'react';
import { useSortable } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import ModernSelect from '../../components/ModernSelect.js';
import type { SortableChannelRowProps } from './types.js';
import {
  buildFixedTokenOptionDescription,
  buildFixedTokenOptionLabel,
  describeTokenBinding,
  resolveTokenBindingConnectionMode,
} from './tokenBindingPresentation.js';
import { getChannelDecisionState, getPriorityTagStyle, getProbabilityColor } from './utils.js';

export function SortableChannelRow({
  channel,
  displayPriority,
  showPriorityBadge = true,
  decisionCandidate,
  isExactRoute,
  loadingDecision,
  isSavingPriority,
  readOnly = false,
  channelManagementDisabled = false,
  mobile = false,
  tokenOptions,
  activeTokenId,
  isUpdatingToken,
  onTokenDraftChange,
  onSaveToken,
  onDeleteChannel,
  onToggleEnabled,
  onSiteBlockModel,
}: SortableChannelRowProps) {
  const {
    attributes,
    listeners,
    setNodeRef,
    setActivatorNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({
    id: channel.id,
    disabled: isSavingPriority || readOnly,
  });

  const resolvedPriority = displayPriority ?? channel.priority ?? 0;
  const managementLocked = readOnly || channelManagementDisabled;

  const rowStyle: CSSProperties = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.72 : channel.enabled === false ? 0.5 : 1,
    zIndex: isDragging ? 10 : 1,
    display: 'grid',
    gridTemplateColumns: managementLocked || mobile ? 'minmax(0, 1fr)' : 'minmax(0, 1fr) auto auto auto',
    alignItems: mobile ? 'stretch' : 'center',
    gap: 8,
    padding: mobile ? '10px 12px' : '8px 12px',
    borderLeft: '2px solid var(--color-primary)',
    borderBottom: '1px solid var(--color-border)',
    borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
    background: isDragging ? 'rgba(59,130,246,0.08)' : 'var(--color-bg-card, rgba(79,70,229,0.02))',
    boxShadow: isDragging ? 'var(--shadow-sm)' : 'none',
  };

  const decisionState = getChannelDecisionState(decisionCandidate, channel, isExactRoute, loadingDecision);
  const tokenBinding = describeTokenBinding(
    tokenOptions,
    activeTokenId,
    channel.token?.name ?? null,
    {
      connectionMode: resolveTokenBindingConnectionMode(channel.account),
      accountName: channel.account?.username || `account-${channel.accountId}`,
    },
  );

  const [mobileDetailsOpen, setMobileDetailsOpen] = useState(false);

  if (mobile) {
    return (
      <div ref={setNodeRef} style={{ ...rowStyle, display: 'block' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
          <button
            type="button"
            ref={setActivatorNodeRef}
            {...attributes}
            {...listeners}
            disabled={isSavingPriority || readOnly}
            className="btn btn-ghost"
            style={{
              width: 22,
              minWidth: 22,
              height: 22,
              padding: 0,
              border: '1px solid var(--color-border-light)',
              color: 'var(--color-text-muted)',
              cursor: isSavingPriority || readOnly ? 'not-allowed' : 'grab',
              opacity: readOnly ? 0.65 : 1,
              marginTop: 2,
            }}
            data-tooltip={readOnly ? '该路由当前不可编辑优先级' : '拖拽调整优先级桶'}
            aria-label="拖拽调整优先级桶"
          >
            <svg width="12" height="12" fill="currentColor" viewBox="0 0 12 12" aria-hidden>
              <circle cx="3" cy="2" r="1" />
              <circle cx="9" cy="2" r="1" />
              <circle cx="3" cy="6" r="1" />
              <circle cx="9" cy="6" r="1" />
              <circle cx="3" cy="10" r="1" />
              <circle cx="9" cy="10" r="1" />
            </svg>
          </button>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minWidth: 0, flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              {showPriorityBadge ? (
                <span
                  className="badge"
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: 0.1,
                    ...getPriorityTagStyle(resolvedPriority),
                  }}
                >
                  P{resolvedPriority}
                </span>
              ) : null}

              <span style={{ fontWeight: 600, color: 'var(--color-text-primary)', fontSize: 14, minWidth: 0 }}>
                {channel.account?.username || `account-${channel.accountId}`}
              </span>

              <span className="badge badge-muted" style={{ fontSize: 10 }}>
                {channel.site?.name || 'unknown'}
              </span>

              <span style={{ fontSize: 11, color: 'var(--color-text-muted)', marginLeft: 'auto' }}>
                成功/失败 <span style={{ color: 'var(--color-success)', fontWeight: 600 }}>{channel.successCount || 0}</span>
                <span style={{ color: 'var(--color-text-muted)', margin: '0 2px' }}>/</span>
                <span style={{ color: 'var(--color-danger)', fontWeight: 600 }}>{channel.failCount || 0}</span>
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              <span
                className="badge"
                style={{
                  fontSize: 10,
                  background: tokenBinding.badgeTone === 'info'
                    ? 'color-mix(in srgb, var(--color-info) 15%, transparent)'
                    : 'color-mix(in srgb, var(--color-warning) 15%, transparent)',
                  color: tokenBinding.badgeTone === 'info' ? 'var(--color-info)' : 'var(--color-warning)',
                }}
              >
                {tokenBinding.bindingModeLabel}
              </span>

              <span
                className="badge"
                style={{
                  fontSize: 10,
                  background: 'color-mix(in srgb, var(--color-primary) 10%, transparent)',
                  color: 'var(--color-primary)',
                  maxWidth: 220,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
                data-tooltip={`当前生效：${tokenBinding.effectiveTokenName}`}
              >
                当前生效：{tokenBinding.effectiveTokenName}
              </span>

              {channel.sourceModel ? (
                <span className="badge badge-info" style={{ fontSize: 10 }}>
                  {channel.sourceModel}
                </span>
              ) : null}

              {channel.manualOverride ? (
                <span
                  className="badge badge-warning"
                  style={{ fontSize: 10 }}
                  data-tooltip="该通道由用户手动添加，而非系统自动生成"
                >
                  手动配置
                </span>
              ) : null}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 11, color: 'var(--color-text-muted)', whiteSpace: 'nowrap' }}>选中概率</span>
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, minWidth: 120 }}>
                <div
                  data-tooltip={decisionState.probability <= 0 ? decisionState.reasonText : undefined}
                  style={{
                    width: 80,
                    height: 6,
                    background: 'var(--color-border)',
                    borderRadius: 999,
                    overflow: 'hidden',
                  }}
                >
                  <div
                    style={{
                      width: `${Math.max(0, Math.min(100, decisionState.probability))}%`,
                      height: '100%',
                      background: getProbabilityColor(decisionState.probability),
                      borderRadius: 999,
                      transition: 'width 0.3s ease',
                    }}
                  />
                </div>
                <span
                  data-tooltip={decisionState.probability <= 0 ? decisionState.reasonText : undefined}
                  style={{
                    fontSize: 11,
                    color: decisionState.probability > 0 ? 'var(--color-text-secondary)' : decisionState.reasonColor,
                    fontVariantNumeric: 'tabular-nums',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {decisionState.probability.toFixed(1)}%
                </span>
              </div>

              {!managementLocked && (
                <button
                  type="button"
                  className="btn btn-link"
                  onClick={() => setMobileDetailsOpen((current) => !current)}
                  style={{ marginLeft: 'auto' }}
                >
                  {mobileDetailsOpen ? '收起配置' : '配置通道'}
                </button>
              )}
            </div>

            {!managementLocked && mobileDetailsOpen && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, paddingTop: 8, borderTop: '1px solid var(--color-border-light)' }}>
                <div style={{ width: '100%' }}>
                  <ModernSelect
                    size="sm"
                    value={String(activeTokenId || 0)}
                    onChange={(nextValue) => onTokenDraftChange(channel.id, Number.parseInt(nextValue, 10) || 0)}
                    disabled={isUpdatingToken}
                    options={[
                      {
                        value: '0',
                        label: tokenBinding.followOptionLabel,
                        description: tokenBinding.followOptionDescription,
                      },
                      ...tokenOptions.map((token) => ({
                        value: String(token.id),
                        label: buildFixedTokenOptionLabel(token, { includeDefaultTag: true }),
                        description: buildFixedTokenOptionDescription(token),
                      })),
                    ]}
                    placeholder="选择令牌绑定方式"
                  />
                  <div style={{ marginTop: 4, fontSize: 11, color: 'var(--color-text-muted)', lineHeight: 1.4 }}>
                    {tokenBinding.helperText}
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 12, flexWrap: 'wrap' }}>
                  <button
                    onClick={onSaveToken}
                    disabled={isUpdatingToken}
                    className="btn btn-link btn-link-info"
                  >
                    {isUpdatingToken ? <span className="spinner spinner-sm" /> : '保存'}
                  </button>

                  <button
                    onClick={() => onToggleEnabled(channel.enabled === false)}
                    className={`btn btn-link ${channel.enabled === false ? 'btn-link-info' : 'btn-link-warning'}`}
                  >
                    {channel.enabled === false ? '启用' : '禁用'}
                  </button>

                  {onSiteBlockModel && channel.site?.id ? (
                    <button
                      onClick={onSiteBlockModel}
                      className="btn btn-link btn-link-warning"
                    >
                      站点屏蔽
                    </button>
                  ) : null}

                  <button
                    onClick={onDeleteChannel}
                    className="btn btn-link btn-link-danger"
                  >
                    移除
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div ref={setNodeRef} style={rowStyle}>
      <div style={{ display: 'flex', alignItems: mobile ? 'stretch' : 'center', flexDirection: mobile ? 'column' : 'row', gap: 10, fontSize: 13, flexWrap: 'wrap', minWidth: 0 }}>
        <button
          type="button"
          ref={setActivatorNodeRef}
          {...attributes}
          {...listeners}
          disabled={isSavingPriority || readOnly}
          className="btn btn-ghost"
          style={{
            width: 22,
            minWidth: 22,
            height: 22,
            padding: 0,
            border: '1px solid var(--color-border-light)',
            color: 'var(--color-text-muted)',
            cursor: isSavingPriority || readOnly ? 'not-allowed' : 'grab',
            opacity: readOnly ? 0.65 : 1,
          }}
          data-tooltip={readOnly ? '该路由当前不可编辑优先级' : '拖拽调整优先级桶'}
          aria-label="拖拽调整优先级桶"
        >
          <svg width="12" height="12" fill="currentColor" viewBox="0 0 12 12" aria-hidden>
            <circle cx="3" cy="2" r="1" />
            <circle cx="9" cy="2" r="1" />
            <circle cx="3" cy="6" r="1" />
            <circle cx="9" cy="6" r="1" />
            <circle cx="3" cy="10" r="1" />
            <circle cx="9" cy="10" r="1" />
          </svg>
        </button>

        {showPriorityBadge ? (
          <span
            className="badge"
            style={{
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: 0.1,
              ...getPriorityTagStyle(resolvedPriority),
            }}
          >
            P{resolvedPriority}
          </span>
        ) : null}

        <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
          {channel.account?.username || `account-${channel.accountId}`}
        </span>

        <span className="badge badge-muted" style={{ fontSize: 10 }}>
          {channel.site?.name || 'unknown'}
        </span>

        <span
          className="badge"
          style={{
            fontSize: 10,
            background: tokenBinding.badgeTone === 'info'
              ? 'color-mix(in srgb, var(--color-info) 15%, transparent)'
              : 'color-mix(in srgb, var(--color-warning) 15%, transparent)',
            color: tokenBinding.badgeTone === 'info' ? 'var(--color-info)' : 'var(--color-warning)',
          }}
        >
          {tokenBinding.bindingModeLabel}
        </span>

        <span
          className="badge"
          style={{
            fontSize: 10,
            background: 'color-mix(in srgb, var(--color-primary) 10%, transparent)',
            color: 'var(--color-primary)',
            maxWidth: 220,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
          data-tooltip={`当前生效：${tokenBinding.effectiveTokenName}`}
        >
          当前生效：{tokenBinding.effectiveTokenName}
        </span>

        {channel.sourceModel ? (
          <span className="badge badge-info" style={{ fontSize: 10 }}>
            {channel.sourceModel}
          </span>
        ) : null}

        {channel.manualOverride ? (
          <span
            className="badge badge-warning"
            style={{ fontSize: 10 }}
            data-tooltip="该通道由用户手动添加，而非系统自动生成"
          >
            手动配置
          </span>
        ) : null}

        {channel.enabled === false ? (
          <span className="badge badge-muted" style={{ fontSize: 10 }}>已禁用</span>
        ) : null}

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', marginTop: mobile ? 0 : 4, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, color: 'var(--color-text-muted)', whiteSpace: 'nowrap' }}>选中概率</span>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, minWidth: 120 }}>
            <div
              data-tooltip={decisionState.probability <= 0 ? decisionState.reasonText : undefined}
              style={{
                width: 80,
                height: 6,
                background: 'var(--color-border)',
                borderRadius: 999,
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  width: `${Math.max(0, Math.min(100, decisionState.probability))}%`,
                  height: '100%',
                  background: getProbabilityColor(decisionState.probability),
                  borderRadius: 999,
                  transition: 'width 0.3s ease',
                }}
              />
            </div>
            <span
              data-tooltip={decisionState.probability <= 0 ? decisionState.reasonText : undefined}
              style={{
                fontSize: 11,
                color: decisionState.probability > 0 ? 'var(--color-text-secondary)' : decisionState.reasonColor,
                fontVariantNumeric: 'tabular-nums',
                whiteSpace: 'nowrap',
              }}
            >
              {decisionState.probability.toFixed(1)}%
            </span>
          </div>

          <span style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>成功/失败</span>
          <span style={{ fontSize: 11 }}>
            <span style={{ color: 'var(--color-success)', fontWeight: 600 }}>{channel.successCount || 0}</span>
            <span style={{ color: 'var(--color-text-muted)', margin: '0 2px' }}>/</span>
            <span style={{ color: 'var(--color-danger)', fontWeight: 600 }}>{channel.failCount || 0}</span>
          </span>
        </div>
      </div>

      {!managementLocked ? (
        mobile ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, width: '100%' }}>
            <div style={{ width: '100%' }}>
              <ModernSelect
                size="sm"
                value={String(activeTokenId || 0)}
                onChange={(nextValue) => onTokenDraftChange(channel.id, Number.parseInt(nextValue, 10) || 0)}
                disabled={isUpdatingToken}
                options={[
                  {
                    value: '0',
                    label: tokenBinding.followOptionLabel,
                    description: tokenBinding.followOptionDescription,
                  },
                  ...tokenOptions.map((token) => ({
                    value: String(token.id),
                    label: buildFixedTokenOptionLabel(token, { includeDefaultTag: true }),
                    description: buildFixedTokenOptionDescription(token),
                  })),
                ]}
                placeholder="选择令牌绑定方式"
              />
              <div style={{ marginTop: 4, fontSize: 11, color: 'var(--color-text-muted)', lineHeight: 1.4 }}>
                {tokenBinding.helperText}
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 12, flexWrap: 'wrap' }}>
              <button
                onClick={onSaveToken}
                disabled={isUpdatingToken}
                className="btn btn-link btn-link-info"
              >
                {isUpdatingToken ? <span className="spinner spinner-sm" /> : '保存'}
              </button>

              <button
                onClick={() => onToggleEnabled(channel.enabled === false)}
                className={`btn btn-link ${channel.enabled === false ? 'btn-link-info' : 'btn-link-warning'}`}
              >
                {channel.enabled === false ? '启用' : '禁用'}
              </button>

              {onSiteBlockModel && channel.site?.id ? (
                <button
                  onClick={onSiteBlockModel}
                  className="btn btn-link btn-link-warning"
                >
                  站点屏蔽
                </button>
              ) : null}

              <button
                onClick={onDeleteChannel}
                className="btn btn-link btn-link-danger"
              >
                移除
              </button>
            </div>
          </div>
        ) : (
          <>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <div style={{ minWidth: 220, flex: 1 }}>
                <ModernSelect
                  size="sm"
                  value={String(activeTokenId || 0)}
                  onChange={(nextValue) => onTokenDraftChange(channel.id, Number.parseInt(nextValue, 10) || 0)}
                  disabled={isUpdatingToken}
                  options={[
                    {
                      value: '0',
                      label: tokenBinding.followOptionLabel,
                      description: tokenBinding.followOptionDescription,
                    },
                    ...tokenOptions.map((token) => ({
                      value: String(token.id),
                      label: buildFixedTokenOptionLabel(token, { includeDefaultTag: true }),
                      description: buildFixedTokenOptionDescription(token),
                    })),
                  ]}
                  placeholder="选择令牌绑定方式"
                />
                <div style={{ marginTop: 4, fontSize: 11, color: 'var(--color-text-muted)', lineHeight: 1.4 }}>
                  {tokenBinding.helperText}
                </div>
              </div>
              <button
                onClick={onSaveToken}
                disabled={isUpdatingToken}
                className="btn btn-link btn-link-info"
              >
                {isUpdatingToken ? <span className="spinner spinner-sm" /> : '保存'}
              </button>
            </div>

            <button
              onClick={() => onToggleEnabled(channel.enabled === false)}
              className={`btn btn-link ${channel.enabled === false ? 'btn-link-info' : 'btn-link-warning'}`}
              data-tooltip={channel.enabled === false ? '启用此通道' : '禁用此通道'}
            >
              {channel.enabled === false ? '启用' : '禁用'}
            </button>

            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              {onSiteBlockModel && channel.site?.id ? (
                <button
                  onClick={onSiteBlockModel}
                  className="btn btn-link btn-link-warning"
                  data-tooltip={`将此模型加入站点「${channel.site?.name || '未知'}」的禁用列表，rebuild 后该站点的此模型通道将不再生成`}
                >
                  站点屏蔽
                </button>
              ) : null}

              <button
                onClick={onDeleteChannel}
                className="btn btn-link btn-link-danger"
              >
                移除
              </button>
            </div>
          </>
        )
      ) : null}
    </div>
  );
}

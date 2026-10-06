"""Deterministic, entirely fictitious bank records and approved business tasks."""

from datetime import datetime, timezone, timedelta
import random

from .models import BusinessTask, Employee


BANK_TZ = timezone(timedelta(hours=8))
REGIONS = [f"合成区域{index:02d}" for index in range(1, 21)]
ROLE_RESOURCES = {
    "客户经理": {"customers", "accounts", "transactions"},
    "信贷专员": {"customers", "accounts", "loans"},
    "运营专员": {"customers", "accounts", "transactions"},
    "审计专员": {"customers", "accounts", "transactions", "loans"},
}


def build_bank(seed: int = 42, customer_count: int = 5000) -> dict:
    """Create referentially linked synthetic rows; identifiers are unusable as bank IDs."""
    if not 1 <= customer_count <= 50000:
        raise ValueError("customer_count must be in 1..50000")
    rng = random.Random(seed)
    employees, tasks = [], []
    roles = list(ROLE_RESOURCES)
    departments = {"客户经理": "零售金融部", "信贷专员": "信贷业务部", "运营专员": "运营管理部", "审计专员": "审计部"}
    for index in range(1, 101):
        role = roles[(index - 1) % len(roles)]
        employee = Employee(
            id=f"E{index:04d}", name=f"合成员工{index:03d}", role=role,
            department=departments[role], region=REGIONS[(index - 1) % len(REGIONS)],
            known_device=f"SYN-DEV-{index:04d}", baseline_daily_records=rng.randint(24, 42),
            baseline_daily_queries=rng.randint(8, 16),
        )
        employees.append(employee)
        common = dict(employee_id=employee.id,
                      valid_from=datetime(2026, 1, 1, tzinfo=BANK_TZ),
                      valid_until=datetime(2026, 12, 31, 23, 59, 59, tzinfo=BANK_TZ))
        tasks.append(BusinessTask(
            id=f"T{index * 2 - 1:05d}", purpose="客户服务", regions=[employee.region],
            max_records=employee.baseline_daily_records, allowed_hours=list(range(8, 19)), **common,
        ))
        tasks.append(BusinessTask(
            id=f"T{index * 2:05d}", purpose="经审批的合成数据对账", regions=REGIONS,
            max_records=50000, allowed_hours=list(range(24)), allow_export=True,
            approved_channels=["internal", "approved_partner", "internal_ai"], **common,
        ))
    customers = [{
        "id": f"SYN-C-{index:06d}", "name": f"合成客户{index:06d}",
        "contact": f"synthetic-{index:06d}@example.invalid",
        "identity_ref": f"SYN-IDENTITY-{index:06d}", "region": REGIONS[index % len(REGIONS)],
        "employee_id": employees[index % len(employees)].id, "synthetic": True,
    } for index in range(1, customer_count + 1)]
    account_count = max(1, round(customer_count * 1.6))
    accounts = [{
        "id": f"SYN-A-{index:07d}", "customer_id": customers[(index - 1) % customer_count]["id"],
        "currency": "CNY", "balance_cents": rng.randint(0, 25000000), "synthetic": True,
    } for index in range(1, account_count + 1)]
    transactions = [{
        "id": f"SYN-TX-{index:08d}", "account_id": accounts[index % account_count]["id"],
        "amount_cents": rng.randint(100, 1000000),
        "timestamp": (datetime(2026, 9, 1, 8, tzinfo=BANK_TZ) + timedelta(seconds=index * 31)).isoformat(),
        "direction": "credit" if index % 2 else "debit", "synthetic": True,
    } for index in range(1, customer_count * 4 + 1)]
    loans = [{
        "id": f"SYN-L-{index:06d}", "customer_id": customers[(index * 7) % customer_count]["id"],
        "principal_cents": rng.randint(1000000, 50000000), "status": "synthetic_active", "synthetic": True,
    } for index in range(1, max(1, customer_count // 8) + 1)]
    counts = {"employees": len(employees), "customers": len(customers), "accounts": len(accounts),
              "transactions": len(transactions), "loans": len(loans), "business_tasks": len(tasks)}
    return {"employees": employees, "tasks": tasks, "customers": customers, "accounts": accounts,
            "transactions": transactions, "loans": loans,
            "manifest": {"synthetic": True, "seed": seed, "counts": counts,
                         "generator_version": "synthetic-bank-v1", "scaled_for_local_poc": True,
                         "notice": "全部为合成测试数据；不对应真实客户、账户、员工或银行系统。"}}

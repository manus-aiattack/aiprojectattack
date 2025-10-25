"""
Constraint Solver using Z3
Solves symbolic constraints to generate concrete inputs
"""

import asyncio
from typing import List, Dict, Optional, Any
import logging

log = logging.getLogger(__name__)

# Try to import Z3
try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    log.warning("[ConstraintSolver] Z3 not available, using fallback solver")


class Constraint:
    """Represents a symbolic constraint"""
    
    def __init__(self, expression: str, variables: List[str] = None):
        self.expression = expression
        self.variables = variables or []
    
    def __repr__(self):
        return f"Constraint({self.expression})"


class ConstraintSolver:
    """
    Constraint Solver using Z3 SMT Solver
    
    Solves symbolic constraints to find concrete values
    that satisfy the constraints.
    """
    
    def __init__(self):
        self.solver = None
        self.variables = {}
        self.constraints = []
        
        if Z3_AVAILABLE:
            self.solver = z3.Solver()
    
    async def add_variable(self, name: str, var_type: str = "int", bit_size: int = 32):
        """
        Add a symbolic variable
        
        Args:
            name: Variable name
            var_type: Variable type (int, bool, bitvec)
            bit_size: Bit size for bitvec
        """
        if not Z3_AVAILABLE:
            self.variables[name] = {'type': var_type, 'bit_size': bit_size}
            return
        
        if var_type == "int":
            self.variables[name] = z3.Int(name)
        elif var_type == "bool":
            self.variables[name] = z3.Bool(name)
        elif var_type == "bitvec":
            self.variables[name] = z3.BitVec(name, bit_size)
        else:
            raise ValueError(f"Unknown variable type: {var_type}")
    
    async def add_constraint(self, constraint: str):
        """
        Add a constraint
        
        Args:
            constraint: Constraint expression (e.g., "x > 10", "x + y == 100")
        """
        if not Z3_AVAILABLE:
            self.constraints.append(constraint)
            log.debug(f"[ConstraintSolver] Added constraint (fallback): {constraint}")
            return
        
        try:
            # Parse constraint expression
            # This is a simplified parser - in production use proper parsing
            constraint_expr = eval(constraint, {"__builtins__": {}}, self.variables)
            
            self.solver.add(constraint_expr)
            self.constraints.append(constraint)
            
            log.debug(f"[ConstraintSolver] Added constraint: {constraint}")
            
        except Exception as e:
            log.error(f"[ConstraintSolver] Failed to add constraint '{constraint}': {e}")
    
    async def solve(self) -> Optional[Dict[str, Any]]:
        """
        Solve constraints and return concrete values
        
        Returns:
            Dictionary mapping variable names to concrete values, or None if unsatisfiable
        """
        if not Z3_AVAILABLE:
            return await self._fallback_solve()
        
        log.info(f"[ConstraintSolver] Solving {len(self.constraints)} constraints...")
        
        result = self.solver.check()
        
        if result == z3.sat:
            model = self.solver.model()
            
            solution = {}
            for var_name, var in self.variables.items():
                value = model[var]
                if value is not None:
                    solution[var_name] = value.as_long() if hasattr(value, 'as_long') else str(value)
            
            log.info(f"[ConstraintSolver] Solution found: {solution}")
            return solution
        
        elif result == z3.unsat:
            log.warning("[ConstraintSolver] Constraints are unsatisfiable")
            return None
        
        else:  # unknown
            log.warning("[ConstraintSolver] Solver returned unknown")
            return None
    
    async def _fallback_solve(self) -> Optional[Dict[str, Any]]:
        """Fallback solver when Z3 is not available"""
        
        log.info("[ConstraintSolver] Using fallback solver...")
        
        # Simple heuristic solver
        solution = {}
        
        for var_name, var_info in self.variables.items():
            # Assign default values
            if var_info['type'] == 'int':
                solution[var_name] = 0
            elif var_info['type'] == 'bool':
                solution[var_name] = False
            elif var_info['type'] == 'bitvec':
                solution[var_name] = 0
        
        return solution
    
    async def is_satisfiable(self) -> bool:
        """Check if constraints are satisfiable"""
        
        if not Z3_AVAILABLE:
            return True  # Assume satisfiable in fallback mode
        
        result = self.solver.check()
        return result == z3.sat
    
    async def get_all_solutions(self, max_solutions: int = 10) -> List[Dict[str, Any]]:
        """
        Get multiple solutions
        
        Args:
            max_solutions: Maximum number of solutions to find
        
        Returns:
            List of solutions
        """
        if not Z3_AVAILABLE:
            solution = await self._fallback_solve()
            return [solution] if solution else []
        
        solutions = []
        
        for i in range(max_solutions):
            result = self.solver.check()
            
            if result != z3.sat:
                break
            
            model = self.solver.model()
            
            solution = {}
            blocking_clause = []
            
            for var_name, var in self.variables.items():
                value = model[var]
                if value is not None:
                    solution[var_name] = value.as_long() if hasattr(value, 'as_long') else str(value)
                    blocking_clause.append(var != value)
            
            solutions.append(solution)
            
            # Block this solution
            if blocking_clause:
                self.solver.add(z3.Or(blocking_clause))
        
        log.info(f"[ConstraintSolver] Found {len(solutions)} solutions")
        
        return solutions
    
    async def simplify_constraints(self):
        """Simplify constraints"""
        
        if not Z3_AVAILABLE:
            return
        
        # Z3 automatically simplifies, but we can force it
        self.solver.simplify()
    
    def reset(self):
        """Reset solver state"""
        
        if Z3_AVAILABLE:
            self.solver.reset()
        
        self.variables.clear()
        self.constraints.clear()
    
    def get_statistics(self) -> Dict:
        """Get solver statistics"""
        
        stats = {
            'num_constraints': len(self.constraints),
            'num_variables': len(self.variables),
            'z3_available': Z3_AVAILABLE
        }
        
        if Z3_AVAILABLE and self.solver:
            stats['z3_stats'] = str(self.solver.statistics())
        
        return stats


if __name__ == '__main__':
    async def test():
        solver = ConstraintSolver()
        
        # Add variables
        await solver.add_variable('x', 'int')
        await solver.add_variable('y', 'int')
        
        # Add constraints
        await solver.add_constraint('x > 10')
        await solver.add_constraint('y < 20')
        await solver.add_constraint('x + y == 25')
        
        # Solve
        solution = await solver.solve()
        
        if solution:
            print(f"Solution: {solution}")
        else:
            print("No solution found")
        
        # Get statistics
        print(f"Statistics: {solver.get_statistics()}")
    
    asyncio.run(test())


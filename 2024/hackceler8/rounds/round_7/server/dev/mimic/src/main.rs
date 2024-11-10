use rand::distributions::Uniform;
use rand::prelude::*;
use serde::Serialize;
use z3::ast::Ast;
use z3::*;

use std::ops::Not;

const CHESTS_PER_ROW: usize = 4;
const CHESTS_PER_COLUMN: usize = 4;

const NUM_MIMICS_MIN: usize = 4;
const NUM_MIMICS_MAX: usize = 5;

#[derive(Copy, Clone, Debug)]
enum Constraint {
    IsNotAMimic,
    MimicsInRow(usize),
    MimicsInColumn(usize),
    MimicsAdjacent(usize),
}

impl Constraint {
    fn random(rng: &mut impl Rng) -> Constraint {
        let options = Uniform::from(0..4);
        let in_row = Uniform::from(0..(NUM_MIMICS_MAX.min(CHESTS_PER_ROW)));
        let in_col = Uniform::from(0..(NUM_MIMICS_MAX.min(CHESTS_PER_COLUMN)));
        let adjacent = Uniform::from(0..(NUM_MIMICS_MAX.min(4)));
        match options.sample(rng) {
            0 => Constraint::IsNotAMimic,
            1 => Constraint::MimicsInRow(in_row.sample(rng)),
            2 => Constraint::MimicsInColumn(in_col.sample(rng)),
            3 => Constraint::MimicsAdjacent(adjacent.sample(rng)),
            _ => unreachable!(),
        }
    }

    fn to_string(self) -> String {
        match self {
            Constraint::IsNotAMimic => "I am not a mimic".to_string(),
            Constraint::MimicsInRow(n) => format!("There are {n} mimics in this row!"),
            Constraint::MimicsInColumn(n) => format!("There are {n} mimics in this column!"),
            Constraint::MimicsAdjacent(n) => format!("There are {n} mimics adjacent to me!"),
        }
    }
}

type ConstantMap<'ctx> = std::collections::HashMap<(usize, usize), ast::Int<'ctx>>;

impl Constraint {
    fn add_z3_constraints(
        self,
        x: usize,
        y: usize,
        ctx: &Context,
        solver: &Solver,
        constants: &ConstantMap,
    ) {
        let we_are_mimic = constants
            .get(&(x, y))
            .unwrap()
            ._eq(&ast::Int::from_i64(&ctx, 1));
        let we_are_not_mimic = constants
            .get(&(x, y))
            .unwrap()
            ._eq(&ast::Int::from_i64(&ctx, 0));
        match self {
            Constraint::IsNotAMimic => {
                // No information here.
            }
            Constraint::MimicsInRow(n) => {
                let row = (0..CHESTS_PER_ROW)
                    .map(|i| constants.get(&(i, y)).unwrap())
                    .collect::<Vec<_>>();
                let row = ast::Int::add(&ctx, &row);
                let cond = &row._eq(&ast::Int::from_i64(&ctx, n as i64));
                solver.assert(&ast::Bool::or(
                    &ctx,
                    &[
                        &ast::Bool::and(&ctx, &[&we_are_mimic, &cond.not()]),
                        &ast::Bool::and(&ctx, &[&we_are_not_mimic, &cond]),
                    ],
                ))
            }
            Constraint::MimicsInColumn(n) => {
                let col = (0..CHESTS_PER_COLUMN)
                    .map(|i| constants.get(&(x, i)).unwrap())
                    .collect::<Vec<_>>();
                let col = ast::Int::add(&ctx, &col);
                let cond = &col._eq(&ast::Int::from_i64(&ctx, n as i64));
                solver.assert(&ast::Bool::or(
                    &ctx,
                    &[
                        &ast::Bool::and(&ctx, &[&we_are_mimic, &cond.not()]),
                        &ast::Bool::and(&ctx, &[&we_are_not_mimic, &cond]),
                    ],
                ))
            }
            Constraint::MimicsAdjacent(n) => {
                // Which offsets are counted as adjacent
                // Note that we're not using diagonals here.
                let offsets = [(-1, 0), (1, 0), (0, -1), (0, 1)];
                let pos = offsets
                    .iter()
                    .filter_map(|(dx, dy)| {
                        constants.get(&((x as i64 + dx) as usize, (y as i64 + dy) as usize))
                    })
                    .collect::<Vec<_>>();
                let pos = ast::Int::add(&ctx, &pos);
                let cond = &pos._eq(&ast::Int::from_i64(&ctx, n as i64));
                solver.assert(&ast::Bool::or(
                    &ctx,
                    &[
                        &ast::Bool::and(&ctx, &[&we_are_mimic, &cond.not()]),
                        &ast::Bool::and(&ctx, &[&we_are_not_mimic, &cond]),
                    ],
                ))
            }
            _ => todo!(),
        }
    }
}

#[derive(Debug, Clone)]
struct Chest {
    constraints: Vec<Constraint>,
    // TODO: Additional identifiers?
}

impl Default for Chest {
    fn default() -> Self {
        Self {
            constraints: vec![Constraint::IsNotAMimic],
        }
    }
}

impl Chest {
    fn to_string(&self) -> String {
        self.constraints
            .iter()
            .map(|x| x.to_string())
            .collect::<String>()
    }
}

#[derive(Debug)]
struct Field {
    chests: Vec<Chest>,
}

impl Field {
    fn new(rng: &mut impl Rng) -> Self {
        let mut rv = Self {
            chests: vec![Chest::default(); CHESTS_PER_ROW * CHESTS_PER_COLUMN],
        };
        for x in 0..CHESTS_PER_ROW {
            for y in 0..CHESTS_PER_COLUMN {
                rv.at_mut(x, y).constraints = vec![Constraint::random(rng)];
            }
        }
        rv
    }

    fn at(&self, x: usize, y: usize) -> &Chest {
        &self.chests[x + y * CHESTS_PER_ROW]
    }

    fn at_mut(&mut self, x: usize, y: usize) -> &mut Chest {
        &mut self.chests[x + y * CHESTS_PER_ROW]
    }

    fn build_z3_constants(ctx: &Context) -> ConstantMap {
        let mut map = std::collections::HashMap::new();
        for x in 0..CHESTS_PER_ROW {
            for y in 0..CHESTS_PER_COLUMN {
                map.insert(
                    (x, y),
                    ast::Int::new_const(&ctx, format!("chest_{}_{}", x, y)),
                );
            }
        }
        map
    }

    // We want to have a json eventually I'd say.
    fn to_string(&self) -> String {
        let mut rv = Vec::new();
        for y in 0..CHESTS_PER_COLUMN {
            for x in 0..CHESTS_PER_ROW {
                rv.push(self.at(x, y).to_string());
            }
            rv.push("\n".to_string());
        }
        rv.join("\n")
    }
}

mod state {
    use serde::Serialize;
    #[derive(Serialize)]
    pub struct Chest {
        pub clue: String,
        pub is_mimic: bool,
    }

    #[derive(Serialize)]
    pub struct State {
        pub min_mimics: usize,
        pub max_mimics: usize,
        pub chests: Vec<Chest>,
    }
}

fn main() {
    let cfg = Config::new();
    let Some(Ok(seed)) = std::env::args().nth(1).map(|x| x.parse::<u64>()) else {
        eprintln!("Seed is missing or not a number");
        return;
    };

    let mut rng = SmallRng::seed_from_u64(seed);
    let mut json = "".to_string();
    loop {
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let field = Field::new(&mut rng);
        let constants = Field::build_z3_constants(&ctx);

        for x in 0..CHESTS_PER_ROW {
            for y in 0..CHESTS_PER_COLUMN {
                // Since we're storing the type as int, we need to make sure it can only
                // be zero or one.
                let we_are_mimic = constants
                    .get(&(x, y))
                    .unwrap()
                    ._eq(&ast::Int::from_i64(&ctx, 1));
                let we_are_not_mimic = constants
                    .get(&(x, y))
                    .unwrap()
                    ._eq(&ast::Int::from_i64(&ctx, 0));
                solver.assert(&ast::Bool::or(&ctx, &[&we_are_mimic, &we_are_not_mimic]));
                let chest = field.at(x, y);
                for constraint in &chest.constraints {
                    constraint.add_z3_constraints(x, y, &ctx, &solver, &constants);
                }
            }
        }

        // Add constraint that only NUM_MIMICS are there in total
        let everything = (0..CHESTS_PER_ROW * CHESTS_PER_COLUMN)
            .map(|i| {
                constants
                    .get(&(i % CHESTS_PER_ROW, i / CHESTS_PER_ROW))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let sum = ast::Int::add(&ctx, &everything);

        // Between NUM_MIMICS and NUM_MIMICS+1 mimics
        let cond = &sum.ge(&ast::Int::from_i64(&ctx, NUM_MIMICS_MIN as i64));
        solver.assert(&cond);
        let cond = &sum.le(&ast::Int::from_i64(&ctx, NUM_MIMICS_MAX as i64));
        solver.assert(&cond);

        let mut n = 0;

        while solver.check() == SatResult::Sat {
            let model = solver.get_model().unwrap();
            //print_model(&model, &constants);
            different_model(&ctx, &solver, &model, &constants);
            n += 1;
            let mut state = state::State {
                min_mimics: NUM_MIMICS_MIN,
                max_mimics: NUM_MIMICS_MAX,
                chests: Vec::new(),
            };

            for y in 0..CHESTS_PER_COLUMN {
                for x in 0..CHESTS_PER_ROW {
                    let value = model
                        .eval(constants.get(&(x, y)).unwrap(), false)
                        .unwrap()
                        .as_i64();
                    state.chests.push(state::Chest {
                        clue: field.at(x, y).to_string(),
                        is_mimic: value.unwrap() == 1,
                    });
                }
            }

            json = serde_json::to_string(&state).unwrap();
        }

        if n == 1 {
            println!("{}", json);
            break;
        }
    }
}

fn print_model(model: &Model, constants: &ConstantMap) {
    for y in 0..CHESTS_PER_COLUMN {
        for x in 0..CHESTS_PER_ROW {
            let value = model
                .eval(constants.get(&(x, y)).unwrap(), false)
                .unwrap()
                .as_i64()
                .expect("Didn't get any result?");
            if value == 1 {
                print!("M");
            } else {
                print!("-");
            }
        }
        println!();
    }
    println!();
}

fn different_model(ctx: &Context, solver: &Solver, model: &Model, constants: &ConstantMap) {
    solver.push();
    // I'm sure there is a nicer way to do this.
    let conds = &(0..CHESTS_PER_COLUMN * CHESTS_PER_ROW)
        .map(|i| {
            let x = i % CHESTS_PER_ROW;
            let y = i / CHESTS_PER_ROW;
            let c = constants.get(&(x, y)).unwrap();
            let v = model.eval(c, false).unwrap();
            c._eq(&v)
        })
        .collect::<Vec<_>>();
    let formula = ast::Bool::and(ctx, &conds.iter().map(|i| i).collect::<Vec<_>>());
    solver.assert(&formula.not());
}

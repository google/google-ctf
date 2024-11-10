use rand::distributions::Uniform;
use rand::prelude::*;

const CHESTS_PER_ROW: usize = 4;
const CHESTS_PER_COLUMN: usize = 4;

const NUM_MIMICS_MIN: usize = 6;
const NUM_MIMICS_MAX: usize = 10;

#[derive(Copy, Clone, Debug)]
enum Constraint {
    IsNotAMimic,
    MimicsInRow(usize),
    MimicsInColumn(usize),
    MimicsAdjacent(usize),
}

impl Constraint {
    fn random(rng: &mut impl Rng, adjacent_fields: usize) -> Constraint {
        let options = Uniform::from(0..4);
        let in_row = Uniform::from(0..(NUM_MIMICS_MAX.min(CHESTS_PER_ROW)));
        let in_col = Uniform::from(0..(NUM_MIMICS_MAX.min(CHESTS_PER_COLUMN)));
        let adjacent = Uniform::from(0..(NUM_MIMICS_MAX.min(adjacent_fields)));
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

fn mimic_status_from_mask(mask: usize, x: usize, y: usize) -> Option<bool> {
    if x < CHESTS_PER_ROW && y < CHESTS_PER_COLUMN {
        Some((mask & 1 << (x + y * CHESTS_PER_ROW)) > 0)
    } else {
        None
    }
}

impl Constraint {
    fn verify(self, x: usize, y: usize, mimic_mask: usize) -> bool {
        let we_are_mimic = mimic_status_from_mask(mimic_mask, x, y).unwrap();
        match self {
            Constraint::IsNotAMimic => {
                // No information here.
                true
            }
            Constraint::MimicsInRow(n) => {
                let mimics_in_row: usize = (0..CHESTS_PER_ROW)
                    .map(|i| mimic_status_from_mask(mimic_mask, i, y).unwrap() as usize)
                    .sum();

                if we_are_mimic {
                    mimics_in_row != n
                } else {
                    mimics_in_row == n
                }
            }
            Constraint::MimicsInColumn(n) => {
                let mimics_in_col: usize = (0..CHESTS_PER_COLUMN)
                    .map(|i| mimic_status_from_mask(mimic_mask, x, i).unwrap() as usize)
                    .sum();

                if we_are_mimic {
                    mimics_in_col != n
                } else {
                    mimics_in_col == n
                }
            }
            Constraint::MimicsAdjacent(n) => {
                // Which offsets are counted as adjacent
                // Note that we're not using diagonals here.
                let offsets = [(-1, 0), (1, 0), (0, -1), (0, 1)];
                let adjacent_mimics: usize = offsets
                    .iter()
                    .filter_map(|(dx, dy)| {
                        let x = (x as i64 + dx) as usize;
                        let y = (y as i64 + dy) as usize;
                        mimic_status_from_mask(mimic_mask, x, y)
                    })
                    .map(|x| x as usize)
                    .sum();
                if we_are_mimic {
                    adjacent_mimics != n
                } else {
                    adjacent_mimics == n
                }
            }
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
                // Calculate how many adjacent fields exist so that we do not run in a situation
                // where we only have two neighbors but claim that we have four mimics nearby ;)
                let mut adjacent_fields = 2;
                if x != 0 && x != CHESTS_PER_ROW - 1 {
                    adjacent_fields += 1;
                }
                if y != 0 && y != CHESTS_PER_COLUMN - 1 {
                    adjacent_fields += 1;
                }
                rv.at_mut(x, y).constraints = vec![Constraint::random(rng, adjacent_fields)];
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
    let Some(Ok(seed)) = std::env::args().nth(1).map(|x| x.parse::<u64>()) else {
        eprintln!("Seed is missing or not a number");
        return;
    };

    let mut rng = SmallRng::seed_from_u64(seed);
    let mut json = "".to_string();
    loop {
        let field = Field::new(&mut rng);

        let mut n = 0;

        // We brute-force using 64bit numbers. Less than 64 so that we can represent the upper
        // bound as 64bit number.
        // We probably don't want to use this approach for much bigger grids than 4x4 anyways.
        assert!(CHESTS_PER_COLUMN * CHESTS_PER_ROW < 64);

        // Iterate over all possible mimic options
        'outter: for mimic_status in 0usize..2usize.pow((CHESTS_PER_COLUMN * CHESTS_PER_ROW) as u32)
        {
            // Check total num of mimics
            let num_mimics = mimic_status.count_ones() as usize;
            if num_mimics < NUM_MIMICS_MIN || num_mimics > NUM_MIMICS_MAX {
                continue;
            }

            // Check all constraints
            for x in 0..CHESTS_PER_ROW {
                for y in 0..CHESTS_PER_COLUMN {
                    for constraint in &field.at(x, y).constraints {
                        if !constraint.verify(x, y, mimic_status) {
                            continue 'outter;
                        }
                    }
                }
            }

            // This is a good state -> store
            n += 1;
            print_model(mimic_status);
            let mut state = state::State {
                min_mimics: NUM_MIMICS_MIN,
                max_mimics: NUM_MIMICS_MAX,
                chests: Vec::new(),
            };

            for y in 0..CHESTS_PER_COLUMN {
                for x in 0..CHESTS_PER_ROW {
                    state.chests.push(state::Chest {
                        clue: field.at(x, y).to_string(),
                        is_mimic: mimic_status_from_mask(mimic_status, x, y).unwrap(),
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

fn print_model(mimic_status: usize) {
    for y in 0..CHESTS_PER_COLUMN {
        for x in 0..CHESTS_PER_ROW {
            let value = mimic_status_from_mask(mimic_status, x, CHESTS_PER_COLUMN - y - 1).unwrap();
            if value {
                eprint!("M");
            } else {
                eprint!("-");
            }
        }
        eprintln!();
    }
    eprintln!();
}

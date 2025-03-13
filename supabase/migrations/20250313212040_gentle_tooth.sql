/*
  # Create tables for smart contract analysis

  1. New Tables
    - `analysis_results`
      - `id` (uuid, primary key)
      - `source_code` (text, the contract code being analyzed)
      - `results` (jsonb, the analysis results)
      - `created_at` (timestamp)
      - `user_id` (uuid, foreign key to auth.users)
    
  2. Security
    - Enable RLS on `analysis_results` table
    - Add policies for authenticated users to:
      - Read their own analysis results
      - Create new analysis results
*/

CREATE TABLE IF NOT EXISTS analysis_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_code text NOT NULL,
  results jsonb NOT NULL,
  created_at timestamptz DEFAULT now(),
  user_id uuid REFERENCES auth.users(id)
);

ALTER TABLE analysis_results ENABLE ROW LEVEL SECURITY;

-- Allow users to read their own analysis results
CREATE POLICY "Users can read own analysis results"
  ON analysis_results
  FOR SELECT
  TO authenticated
  USING (auth.uid() = user_id);

-- Allow users to create analysis results
CREATE POLICY "Users can create analysis results"
  ON analysis_results
  FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = user_id);